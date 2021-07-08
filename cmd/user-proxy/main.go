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
	FlagProxyServerHost = "proxy-server-host"
	FlagProxyServerPort = "proxy-server-port"
	FlagCACert          = "ca-cert"
	FlagClientCert      = "client-cert"
	FlagClientKey       = "client-key"
)

const (
	ClusterPort         = 8000
	ClusterRequestProto = "http"
)

type UserServer struct {
	caCert          string
	clientCert      string
	clientKey       string
	proxyServerHost string
	proxyServerPort int
}

func NewUserServer(
	caCert, clientCert, clientKey, proxyServerHost string, proxyServerPort int,
) (*UserServer, error) {
	if caCert != "" {
		if _, err := os.Stat(caCert); os.IsNotExist(err) {
			return nil, err
		}
	}
	if clientCert != "" {
		if _, err := os.Stat(clientCert); os.IsNotExist(err) {
			return nil, err
		}
	}
	if clientKey != "" {
		if _, err := os.Stat(clientKey); os.IsNotExist(err) {
			return nil, err
		}
	}

	return &UserServer{
		caCert:          caCert,
		clientKey:       clientKey,
		clientCert:      clientCert,
		proxyServerHost: proxyServerHost,
		proxyServerPort: proxyServerPort,
	}, nil
}

func (u *UserServer) proxyHandler(wr http.ResponseWriter, req *http.Request) {
	// parse clusterID from current requestURL
	clusterID, kubeAPIPath, err := parseRequestURL(req.RequestURI)
	if err != nil {
		klog.V(4).ErrorS(err, "parse request URL failed")
		return
	}

	// connect with http tunnel
	o := &options{
		mode:         "http-connect",
		caCert:       u.caCert,
		clientKey:    u.clientKey,
		clientCert:   u.clientCert,
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
	dialer, err := getMTLSDialer(o)
	if err != nil {
		klog.V(4).ErrorS(err, "get dialer failed")
		return
	}
	http.DefaultTransport.(*http.Transport).DialContext = dialer

	// restruct new apiserverURL
	apiserverURL, err := url.Parse(fmt.Sprintf("%s://%s:%d/%s", o.requestProto, o.requestHost, o.requestPort, o.requestPath))
	if err != nil {
		klog.V(4).ErrorS(err, "parse restructed URL")
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(apiserverURL)
	proxy.ServeHTTP(wr, req)
}

// parseRequestURL
// Example Input: <service-ip>:8080/<clusterID>/api/pods
// Output:
// 	clusterID: <clusterID>
// 	kubeAPIPath: api/pods
func parseRequestURL(requestURL string) (clusterID string, kubeAPIPath string, err error) {
	paths := strings.Split(requestURL, "/")
	if len(paths) <= 2 {
		err = errors.New("requestURL format not correct")
		return
	}
	clusterID = paths[1]                       // <clusterID>
	kubeAPIPath = strings.Join(paths[2:], "/") // api/pods
	return
}

// options is copy from apiserver-network-proxy/cmd/client/main.go GrpcProxyClientOptions
type options struct {
	clientCert   string
	clientKey    string
	caCert       string
	requestProto string
	requestPath  string
	requestHost  string
	requestPort  int
	proxyHost    string
	proxyPort    int
	mode         string
}

func getMTLSDialer(o *options) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	tlsConfig, err := getClientTLSConfig(o.caCert, o.clientCert, o.clientKey, o.proxyHost, nil)
	if err != nil {
		return nil, err
	}

	var proxyConn net.Conn

	// Setup signal handler
	ch := make(chan os.Signal, 1)
	signal.Notify(ch)

	go func() {
		sig := <-ch
		klog.InfoS("close signal:", sig)
		if proxyConn == nil {
			klog.InfoS("proxyConn is nil")
		} else {
			err := proxyConn.Close()
			klog.ErrorS(err, "connection closed")
		}
	}()

	switch o.mode {
	case "http-connect":
		proxyAddress := fmt.Sprintf("%s:%d", o.proxyHost, o.proxyPort)
		requestAddress := fmt.Sprintf("%s:%d", o.requestHost, o.requestPort)

		proxyConn, err = tls.Dial("tcp", proxyAddress, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("dialing proxy %q failed: %v", proxyAddress, err)
		}
		fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", requestAddress, "127.0.0.1")
		br := bufio.NewReader(proxyConn)
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via proxy %s failed: %v",
				requestAddress, proxyAddress, err)
		}
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("proxy error from %s while dialing %s: %v", proxyAddress, requestAddress, res.Status)
		}

		// It's safe to discard the bufio.Reader here and return the
		// original TCP conn directly because we only use this for
		// TLS, and in TLS the client speaks first, so we know there's
		// no unbuffered data. But we can double-check.
		if br.Buffered() > 0 {
			return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT proxy %q",
				br.Buffered(), proxyAddress)
		}
	default:
		return nil, fmt.Errorf("failed to process mode %s", o.mode)
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
			proxyServerHost, _ := cmd.Flags().GetString(FlagProxyServerHost)
			proxyServerPort, _ := cmd.Flags().GetInt(FlagProxyServerPort)
			caCert, _ := cmd.Flags().GetString(FlagCACert)
			clientCert, _ := cmd.Flags().GetString(FlagClientCert)
			clientKey, _ := cmd.Flags().GetString(FlagClientKey)

			us, err := NewUserServer(caCert, clientCert, clientKey, proxyServerHost, proxyServerPort)
			if err != nil {
				klog.V(4).ErrorS(err, "new user server failed")
				return
			}

			http.HandleFunc("/", us.proxyHandler)
			if err := http.ListenAndServe(":"+strconv.Itoa(serverPort), nil); err != nil {
				klog.V(4).ErrorS(err, "listen to http err")
			}
		},
	}

	cmd.Flags().Int(FlagServerPort, 8080, "handle user request using this port")
	cmd.Flags().String(FlagProxyServerHost, "127.0.0.1", "The host of the proxy server.")
	cmd.Flags().Int(FlagProxyServerPort, 8090, "The port the proxy server is listening on.")
	cmd.Flags().String(FlagCACert, "", "We use to validate clients.")
	cmd.Flags().String(FlagClientCert, "", "Secure communication with this cert.")
	cmd.Flags().String(FlagClientKey, "", "Secure communication with this key.")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
