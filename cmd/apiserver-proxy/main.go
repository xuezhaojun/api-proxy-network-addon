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

func proxyHandler(wr http.ResponseWriter, req *http.Request) {
	apiserverURL, err := url.Parse(KUBE_APISERVER_ADDRESS)
	if err != nil {
		klog.Errorf("KUBE_APISERVER_ADDRESS parse error: %s", err.Error())
		return
	}

	klog.V(4).InfoS("requestURL", req.RequestURI)

	if klog.V(4).Enabled() {
		for k, v := range req.Header {
			klog.InfoS("Header:", k, v)
		}
	}

	// TODO temperya add to for test
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IlUzNlg2OURic2pGM2F0ZnRYU0d6dXJINDVBN3dpUm9kcUFZLU1hZi03MXcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tazlja3oiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjkzZTM4ZTRhLWRiNWYtNGEzMi1hOWIxLTVhNmY3OWFkNGZkMCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.xpFr4zRznpvn2BhzQzB0fXtDRQloDuH9jwl6Q00IL7ZDP5Yighe0AyVAMhyi8P2eUqblbEZraOdWs4ifDn7KwQ-NckN-PNOtwsT-9Jzkrd5tAXj2Y25-NzMPe7hdx4Zt4WOcNsmsFsptdp4-UwAahLHA7BUqp_XW6lMT3Z5hkbYtcTR7E7zuRcaAtgCbFHN761zFyy0FvCyU7SYWhm9M2iEmiFt6zTYtyyHq6CU_9WOS910BrQElNXrc-0Z0AHzygl87_ZkGL3moy3RW5IsiSGyrh_OtdVArh5pITODxp0G1NWiAMRmp0fpJnYeRnYn1EaVlDPsy3CEUew4dZObMRg")

	// change the proto from http to https
	req.Proto = "https"

	// skip insecure verify
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	http.DefaultTransport.(*http.Transport).ForceAttemptHTTP2 = false
	if !http.DefaultTransport.(*http.Transport).ForceAttemptHTTP2 && http.DefaultTransport.(*http.Transport).TLSClientConfig != nil {
		klog.V(4).InfoS("not upgrade to http2")
	}

	proxy := httputil.NewSingleHostReverseProxy(apiserverURL)

	if req.Header.Get("Connection") == "Upgrade" && req.Header.Get("Upgrade") == "SPDY/3.1" {
		klog.V(4).InfoS("upgrade to spdy/3.1")
	}

	proxy.ServeHTTP(wr, req)
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
