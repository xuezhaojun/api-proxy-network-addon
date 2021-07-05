package main

import (
	"crypto/tls"
	goflag "flag"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io/ioutil"
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
	KUBE_APISERVER_ADDRESS = "https://kubernetes.default.svc"
	//KUBE_APISERVER_ADDRESS = "https://127.0.0.1:8001" // for local test
	//KUBE_APISERVER_ADDRESS = "https://www.baidu.com" // for local test
)

const (
	FlagProxyPort = "proxy-port"
)

func proxyHandler(wr http.ResponseWriter, req *http.Request) {
	apiserverURL, err := url.Parse(KUBE_APISERVER_ADDRESS)
	if err != nil {
		klog.Errorf("KUBE_APISERVER_ADDRESS parse error: %s", err.Error())
		return
	}
	fmt.Println("request headers:")
	for k, v := range req.Header {
		fmt.Println(k, v)
	}

	// change the proto from http to https
	req.Proto = "https"

	// skip insecure
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	proxy := httputil.NewSingleHostReverseProxy(apiserverURL)
	fmt.Println("begin proxy")
	proxy.ServeHTTP(wr, req)
}

func proxyHandlerWithOutReverseProxy(wr http.ResponseWriter, req *http.Request) {
	//apiserverURL, err := url.Parse(KUBE_APISERVER_ADDRESS)
	//if err != nil {
	//	klog.Errorf("KUBE_APISERVER_ADDRESS parse error: %s",err.Error())
	//	return
	//}
	//fmt.Println("request headers:")
	//for k,v := range req.Header {
	//	fmt.Println(k,v)
	//}

	// change the proto from http to https
	//req.Proto = "https"
	//req.URL = apiserverURL

	// set skpi insecure verify
	//http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// new client and request to access kubeapiserver
	newReq, err := http.NewRequest(req.Method, KUBE_APISERVER_ADDRESS, req.Body)
	if err != nil {
		klog.Errorf("new request %s:", err.Error())
		return
	}

	for k, v := range req.Header {
		newReq.Header.Set(k, v[0])
	}
	for k, v := range newReq.Header {
		fmt.Println(k, v)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(newReq)
	if err != nil {
		klog.Errorf("Do Req Failed %s:", err.Error())
		return
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		klog.Errorf("failed to read response from client, got %v", err)
		return
	}
	klog.V(4).Infof("HTML Response:\n%s\n", string(data))

	_, err = wr.Write(data)
	if err != nil {
		klog.Errorf("failed to write back, got %v", err.Error())
		return
	}
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
			http.HandleFunc("/", proxyHandlerWithOutReverseProxy)
			if err := http.ListenAndServe(":"+strconv.Itoa(port), nil); err != nil {
				klog.Errorf("listen to http err: %s", err.Error())
			}
		},
	}

	cmd.Flags().Int(FlagProxyPort, 8000, "handle request from proxy-agent using this port")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
