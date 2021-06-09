# run proxy-server locally
./bin/proxy-server --server-port=9090 --agent-port=9091  --mode=http-connect --server-ca-cert=certs/master/issued/ca.crt --server-cert=certs/master/issued/proxy-master.crt --server-key=certs/master/private/proxy-master.key --cluster-ca-cert=certs/agent/issued/ca.crt --cluster-cert=certs/agent/issued/proxy-master.crt --cluster-key=certs/agent/private/proxy-master.key --proxy-strategies=destHost
# run spoke1 locally
./bin/proxy-agent --proxy-server-port=9091 --ca-cert=certs/agent/issued/ca.crt --agent-cert=certs/agent/issued/proxy-agent.crt --agent-key=certs/agent/private/proxy-agent.key --agent-identifiers="host=agent1"
# kubectl proxy a cluster to localhost
kubectl proxy --port=8000 --accept-hosts=.*
# run a user-server
./user-server --server-port=8081 --proxy-server-port=9090 --ca-cert=certs/master/issued/ca.crt --client-cert=certs/master/issued/proxy-client.crt --client-key=certs/master/private/proxy-client.key
