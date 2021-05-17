kind load docker-image proxyserver-amd64:1.0.0 --name=hub
kind load docker-image proxyagent-amd64:1.0.0 --name=spoke1
kind load docker-image proxyagent-amd64:1.0.0 --name=spoke2

kind load docker-image kubectlproxy:1.0.0 --name=spoke1
kind load docker-image kubectlproxy:1.0.0 --name=spoke2

kind load docker-image userserver:1.0.1 --name=hub