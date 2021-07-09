package main

import (
	"crypto/tls"
	goflag "flag"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
)

const (
	//KUBE_APISERVER_ADDRESS = "https://kubernetes.default.svc"
	KUBE_APISERVER_ADDRESS = "https://kubernetes.default" // for local test
)

const (
	FlagProxyPort = "proxy-port"
)

const (
	DefaultPort = 8000
)

type LogResponseWriter struct {
	wr http.ResponseWriter
}

func (l LogResponseWriter) Header() http.Header {
	return l.wr.Header()
}

func (l LogResponseWriter) Write(bytes []byte) (int, error) {
	klog.V(4).InfoS("response from apiserver:", "response", string(bytes))
	return l.wr.Write(bytes)
}

func (l LogResponseWriter) WriteHeader(statusCode int) {
	l.wr.WriteHeader(statusCode)
}

func proxyHandler(wr http.ResponseWriter, req *http.Request) {
	apiserverURL, err := url.Parse(KUBE_APISERVER_ADDRESS)
	if err != nil {
		klog.Errorf("KUBE_APISERVER_ADDRESS parse error: %s", err.Error())
		return
	}

	klog.V(4).InfoS("requestURL", req.RequestURI)

	if klog.V(4).Enabled() {
		for k,v := range req.Header {
			klog.InfoS("Header:",k,v)
		}
	}

	// change the proto from http to https
	req.Proto = "https"

	// skip insecure verify
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	proxy := httputil.NewSingleHostReverseProxy(apiserverURL)
	proxy.ServeHTTP(LogResponseWriter{wr: wr}, req)
}

func main() {
	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	logs.InitLogs()
	defer logs.FlushLogs()

	cmd := &cobra.Command{
		Use:   "apiserver-proxy",
		Short: "apiserver-proxy",
		Run: func(cmd *cobra.Command, args []string) {
			port, _ := cmd.Flags().GetInt(FlagProxyPort)
			http.HandleFunc("/", proxyHandler)
			if err := http.ListenAndServe(":"+strconv.Itoa(port), nil); err != nil {
				klog.Errorf("listen to http err: %s", err.Error())
			}
		},
	}

	cmd.Flags().Int(FlagProxyPort, DefaultPort, "handle request from proxy-agent using this port")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
