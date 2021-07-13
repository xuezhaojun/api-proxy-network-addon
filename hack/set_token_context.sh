# yp musht install first
# brew install yq

# get token of current context
secret=$(kubectl get serviceaccounts default -oyaml | yq eval '.secrets[0].name' -)
token=$(kubectl get secret $secret -oyaml | yq eval '.data.token' - | base64 -d)

# add cluster role to default service account
cat <<EOF | kubectl apply -f -
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: default-admin
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: ""
EOF

# get current cluster
cc=$(kubectl config current-context)

# set a new user with the token
kubectl config set-credentials john --token=$token

# set a new context
kubectl config set-context john --cluster=$(kubectl config current-context) --user=john