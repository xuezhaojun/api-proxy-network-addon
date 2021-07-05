kind load docker-image proxyserver-amd64:1.0.0 --name=hub
kind load docker-image proxyagent-amd64:1.0.0 --name=cluster1
kind load docker-image proxyagent-amd64:1.0.0 --name=cluster2

kind load docker-image kubectlproxy:1.0.0 --name=cluster1
kind load docker-image kubectlproxy:1.0.0 --name=cluster2

kind load docker-image apiserverproxy:1.0.0 --name=cluster1
kind load docker-image apiserverproxy:1.0.0 --name=cluster2

kind load docker-image userserver:1.0.0 --name=hub