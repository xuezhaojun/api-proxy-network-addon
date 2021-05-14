cd certs
kubectl config use-context kind-hub
kubectl create secret generic certs \
  --from-file=agent-issued-ca.crt=./agent/issued/ca.crt \
  --from-file=agent-issued-proxy-agent.crt=./agent/issued/proxy-agent.crt \
	--from-file=agent-issued-proxy-master.crt=./agent/issued/proxy-master.crt \
	--from-file=agent-private-ca.key=./agent/private/ca.key \
	--from-file=agent-private-proxy-agent.key=./agent/private/proxy-agent.key \
	--from-file=agent-private-proxy-master.key=./agent/private/proxy-master.key \
	--from-file=master-issued-ca.crt=./master/issued/ca.crt \
  --from-file=master-issued-proxy-client.crt=./master/issued/proxy-client.crt \
	--from-file=master-issued-proxy-master.crt=./master/issued/proxy-master.crt \
	--from-file=master-private-ca.key=./master/private/ca.key \
	--from-file=master-private-proxy-client.key=./master/private/proxy-client.key \
	--from-file=master-private-proxy-master.key=./master/private/proxy-master.key
kubectl config use-context kind-spoke1
kubectl create secret generic certs \
  --from-file=agent-issued-ca.crt=./agent/issued/ca.crt \
  --from-file=agent-issued-proxy-agent.crt=./agent/issued/proxy-agent.crt \
	--from-file=agent-issued-proxy-master.crt=./agent/issued/proxy-master.crt \
	--from-file=agent-private-ca.key=./agent/private/ca.key \
	--from-file=agent-private-proxy-agent.key=./agent/private/proxy-agent.key \
	--from-file=agent-private-proxy-master.key=./agent/private/proxy-master.key \
	--from-file=master-issued-ca.crt=./master/issued/ca.crt \
  --from-file=master-issued-proxy-client.crt=./master/issued/proxy-client.crt \
	--from-file=master-issued-proxy-master.crt=./master/issued/proxy-master.crt \
	--from-file=master-private-ca.key=./master/private/ca.key \
	--from-file=master-private-proxy-client.key=./master/private/proxy-client.key \
	--from-file=master-private-proxy-master.key=./master/private/proxy-master.key
kubectl config use-context kind-spoke2
kubectl create secret generic certs \
  --from-file=agent-issued-ca.crt=./agent/issued/ca.crt \
  --from-file=agent-issued-proxy-agent.crt=./agent/issued/proxy-agent.crt \
	--from-file=agent-issued-proxy-master.crt=./agent/issued/proxy-master.crt \
	--from-file=agent-private-ca.key=./agent/private/ca.key \
	--from-file=agent-private-proxy-agent.key=./agent/private/proxy-agent.key \
	--from-file=agent-private-proxy-master.key=./agent/private/proxy-master.key \
	--from-file=master-issued-ca.crt=./master/issued/ca.crt \
  --from-file=master-issued-proxy-client.crt=./master/issued/proxy-client.crt \
	--from-file=master-issued-proxy-master.crt=./master/issued/proxy-master.crt \
	--from-file=master-private-ca.key=./master/private/ca.key \
	--from-file=master-private-proxy-client.key=./master/private/proxy-client.key \
	--from-file=master-private-proxy-master.key=./master/private/proxy-master.key