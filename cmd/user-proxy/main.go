package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	goflag "flag"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io/ioutil"
	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	FlagServerPort      = "server-port"
	FlagProxyUds        = "proxy-uds"
	FlagProxyServerHost = "proxy-server-host"
	FlagProxyServerPort = "proxy-server-port"

	FlagServerCert = "server-cert"
	FlagServerKey  = "server-key"
)

const (
	ClusterPort         = 8000
	ClusterRequestProto = "http"
	ProxyUds            = "/go/src/github.com/open-cluster-management/api-network-proxy-addon/socket"
)

type UserServer struct {
	proxyUdsName    string
	proxyServerHost string
	proxyServerPort int
}

func NewUserServer(
	proxyUdsName, proxyServerHost string, proxyServerPort int,
) (*UserServer, error) {
	return &UserServer{
		proxyUdsName:    proxyUdsName,
		proxyServerHost: proxyServerHost,
		proxyServerPort: proxyServerPort,
	}, nil
}

func (u *UserServer) proxyHandler(wr http.ResponseWriter, req *http.Request) {
	// parse clusterID from current requestURL
	clusterID, kubeAPIPath, err := parseRequestURL(req.RequestURI)
	if err != nil {
		klog.ErrorS(err, "parse request URL failed")
		return
	}

	// connect with http tunnel
	o := &options{
		mode:         "http-connect",
		proxyUdsName: u.proxyUdsName,
		proxyHost:    u.proxyServerHost,
		proxyPort:    u.proxyServerPort,
		requestProto: ClusterRequestProto,
		requestHost:  clusterID,
		requestPort:  ClusterPort,
		requestPath:  kubeAPIPath,
	}

	// skip insecure verify
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// replace dialer with tunnel dialer
	dialer, err := getUDSDialer(o)
	if err != nil {
		klog.ErrorS(err, "get dialer failed")
		return
	}
	http.DefaultTransport.(*http.Transport).DialContext = dialer
	http.DefaultTransport.(*http.Transport).ForceAttemptHTTP2 = false

	// restruct new apiserverURL
	target := fmt.Sprintf("%s://%s:%d", o.requestProto, o.requestHost, o.requestPort)
	apiserverURL, err := url.Parse(target)
	if err != nil {
		klog.ErrorS(err, "parse restructed URL")
		return
	}

	// update request URL path
	req.URL.Path = o.requestPath

	// update proti
	req.Proto = "http"

	klog.V(4).InfoS("request:", "scheme", req.URL.Scheme, "rawQuery", req.URL.RawQuery, "path", req.URL.Path)

	proxy := httputil.NewSingleHostReverseProxy(apiserverURL)
	proxy.ServeHTTP(wr, req)
}

// parseRequestURL
// Example Input: <service-ip>:8080/<clusterID>/api/pods?timeout=32s
// Example Output:
// 	clusterID: <clusterID>
// 	kubeAPIPath: api/pods
func parseRequestURL(requestURL string) (clusterID string, kubeAPIPath string, err error) {
	paths := strings.Split(requestURL, "/")
	if len(paths) <= 2 {
		err = errors.New("requestURL format not correct")
		return
	}
	clusterID = paths[1]                             // <clusterID>
	kubeAPIPath = strings.Join(paths[2:], "/")       // api/pods?timeout=32s
	kubeAPIPath = strings.Split(kubeAPIPath, "?")[0] // api/pods
	return
}

// options is copy from apiserver-network-proxy/cmd/client/main.go GrpcProxyClientOptions
type options struct {
	requestProto string
	requestPath  string
	requestHost  string
	requestPort  int
	proxyUdsName string
	proxyHost    string
	proxyPort    int
	mode         string
}

func getUDSDialer(o *options) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	var proxyConn net.Conn
	var err error

	// Setup signal handler
	ch := make(chan os.Signal, 1)
	signal.Notify(ch)
	go func() {
		for {
			sig := <-ch
			if strings.Contains(sig.String(), "Urgent I/O") {
				klog.V(4).InfoS("listen Urgent I/O but not close the connection")
				continue
			} else {
				if proxyConn == nil {
					klog.InfoS("connect already closed")
				} else if proxyConn != nil {
					err := proxyConn.Close()
					klog.ErrorS(err, "connection closed")
				}
				return
			}
		}
	}()

	requestAddress := fmt.Sprintf("%s:%d", o.requestHost, o.requestPort)

	proxyConn, err = net.Dial("unix", o.proxyUdsName)
	if err != nil {
		return nil, fmt.Errorf("dialing proxy %q failed: %v", o.proxyUdsName, err)
	}
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", requestAddress, "127.0.0.1")
	br := bufio.NewReader(proxyConn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via uds proxy %s failed: %v",
			requestAddress, o.proxyUdsName, err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("proxy error from %s while dialing %s: %v", o.proxyUdsName, requestAddress, res.Status)
	}

	// It's safe to discard the bufio.Reader here and return the
	// original TCP conn directly because we only use this for
	// TLS, and in TLS the client speaks first, so we know there's
	// no unbuffered data. But we can double-check.
	if br.Buffered() > 0 {
		return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT uds proxy %q",
			br.Buffered(), o.proxyUdsName)
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return proxyConn, nil
	}, nil
}

// getClientTLSConfig returns tlsConfig based on x509 certs
func getClientTLSConfig(caFile, certFile, keyFile, serverName string, protos []string) (*tls.Config, error) {
	certPool, err := getCACertPool(caFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	if len(protos) != 0 {
		tlsConfig.NextProtos = protos
	}
	if certFile == "" && keyFile == "" {
		// return TLS config based on CA only
		return tlsConfig, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair %s and %s: %v", certFile, keyFile, err)
	}

	tlsConfig.ServerName = serverName
	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig, nil
}

// getCACertPool loads CA certificates to pool
func getCACertPool(caFile string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert %s: %v", caFile, err)
	}
	ok := certPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, fmt.Errorf("failed to append CA cert to the cert pool")
	}
	return certPool, nil
}

func main() {
	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	logs.InitLogs()
	defer logs.FlushLogs()

	cmd := &cobra.Command{
		Use:   "anp-user-server",
		Short: "anp-user-server",
		Run: func(cmd *cobra.Command, args []string) {
			serverPort, _ := cmd.Flags().GetInt(FlagServerPort)
			proxyUds, _ := cmd.Flags().GetString(FlagProxyUds)
			proxyServerHost, _ := cmd.Flags().GetString(FlagProxyServerHost)
			proxyServerPort, _ := cmd.Flags().GetInt(FlagProxyServerPort)
			serverCert, _ := cmd.Flags().GetString(FlagServerCert)
			serverKey, _ := cmd.Flags().GetString(FlagServerKey)

			us, err := NewUserServer(proxyUds, proxyServerHost, proxyServerPort)
			if err != nil {
				klog.ErrorS(err, "new user server failed")
				return
			}

			http.HandleFunc("/", us.proxyHandler)
			if err := http.ListenAndServeTLS("localhost:"+strconv.Itoa(serverPort), serverCert, serverKey, nil); err != nil {
				klog.ErrorS(err, "listen to http err")
			}
		},
	}

	cmd.Flags().Int(FlagServerPort, 8080, "handle user request using this port")
	cmd.Flags().String(FlagProxyUds, ProxyUds, "the UDS name to connect to")
	cmd.Flags().String(FlagProxyServerHost, "127.0.0.1", "The host of the proxy server.")
	cmd.Flags().Int(FlagProxyServerPort, 8090, "The port the proxy server is listening on.")
	cmd.Flags().String(FlagServerCert, "", "Secure communication with this cert.")
	cmd.Flags().String(FlagServerKey, "", "Secure communication with this key.")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
