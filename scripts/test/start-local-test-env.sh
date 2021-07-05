# run proxy-server locally
./bin/proxy-server --server-port=9090 --agent-port=9091  --mode=http-connect --server-ca-cert=certs/master/issued/ca.crt --server-cert=certs/master/issued/proxy-master.crt --server-key=certs/master/private/proxy-master.key --cluster-ca-cert=certs/agent/issued/ca.crt --cluster-cert=certs/agent/issued/proxy-master.crt --cluster-key=certs/agent/private/proxy-master.key --proxy-strategies=destHost
# run cluster1 locally
./bin/proxy-agent --proxy-server-port=9091 --ca-cert=certs/agent/issued/ca.crt --agent-cert=certs/agent/issued/proxy-agent.crt --agent-key=certs/agent/private/proxy-agent.key --agent-identifiers="host=agent1"
# kubectl proxy a cluster to localhost
kubectl proxy --port=8000 --accept-hosts=".*"
# run a user-server
./user-server --server-port=9081 --proxy-server-port=9090 --ca-cert=certs/master/issued/ca.crt --client-cert=certs/master/issued/proxy-client.crt --client-key=certs/master/private/proxy-client.key

curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjNqdVljOUNGRHVOcGhfa2lhTUY5SzVZTmJKN2JfbE93c1lGX3NMaWVSRXMifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImplbmtpbnMtdG9rZW4td3h2NWsiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiamVua2lucyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjZiMDRkZTc4LTg1OGQtNGI5MC1hZjVjLTgzYTIyYWJkZWE4NiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmplbmtpbnMifQ.MxnzPd8KvCMPKH4aHhn2QMbPANabgh0dHbVrEnDxtUajbKo_BWjAdZNBPU--DIK7rXwvuquDFytzSeeG9Wm-ARdH5nVX_91FwP5ovWs_ErPcnxQhuyxOrStt_Y1NytiWxy-br5aiJVe3q3ZpzIKzChB8PHSd452YCv9E_V6Omlydp9os46tl-fIuq8zyWMTHidDRSu7Fa5mQ0HTprOu8jIz1JAf6h0lRu8rO_rt0p8Df4rQUYm7dfSMjVeCvh1QR3qo5jugGUWAdY1gxcbyzTd6GBTD-HLGn4wNWTy8YUBxxoc4spMHQDJzfdoa77c2rqT0dE6OYsRBkPMmcD9MkKA" -H "User-Agent: kubectl/v1.19.7 (darwin/amd64) kubernetes/1dd5338" -H "Accept: application/json;as=Table;v=v1;g=meta.k8s.io,application/json;as=Table;v=v1beta1;g=meta.k8s.io,application/json" 'http://127.0.0.1:9081/api/v1/namespaces/default/pods?limit=500' --insecure
