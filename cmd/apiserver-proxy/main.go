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

	// TODO only add to for test
	//req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImNuUmtUN3V2MVVERmV6ZmNLWG1oWUlNU2xJMjMzbUVDVzNXVW55QXY0ZzQifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tY25wOWQiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImY5YTg3YzdiLTE5OGUtNGI0MC1iZWEzLWM2NDFkNmJjYmQwZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.UJKrBvv-6kL1O4HDvpACBswz3-Lg4O29Wkg1gmjMr5QqQHce1sXk5YnC8ncDMoaERZah3Mmp71Doa9Fw9kNARMej9q2tYU31qEvY_EMPQMoylB9FV9dTmUQsf9hVduDyQjd2q7nK1Rg1kz8dLOKqqerafk2MmCrXtmeIjTGD4AmkvZ2HgeiEKc3miOEPS7tH-ZRfjiQMOWcL4tIbuIht_22r9mC_g3ivp2yK0o2CmygertVGlu08UePVgVHqGgGidPN6jkPbGepzXHk1PbXdBCy2HFQZuuKMyUl_fZjZY36CvWNG5Pf1q280t4ohu9Bc3snQ_XPWbg-Z44QQRWrItg")

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
