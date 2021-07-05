USER="zhao"
GROUP="MGM"

# create use.crt user.key and csr
openssl genrsa -out $USER.key 2048
openssl req -new -key $USER.key -out $USER.csr -subj "/CN=$USER/O=$GROUP"
REQUEST=$(cat $USER.csr | base64 | tr -d "\n")

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $USER
spec:
  groups:
  - system:authenticated
  request: $REQUEST
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF

kubectl certificate approve $USER
kubectl get csr/$USER -o yaml

# create role
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: default
rules:
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - create
      - get
      - list
      - update
      - delete
EOF

# create role binding
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding-$USER
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: developer
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: $USER
EOF

# get crt from csr
kubectl get certificatesigningrequests.certificates.k8s.io $USER -o jsonpath='{.status.certificate}' | base64 -d > $USER.crt

# add user to kubeconfig
kubectl config unset users.$USER
kubectl config set-credentials $USER --client-key=$USER.key --client-certificate=$USER.crt --embed-certs=true
kubectl config set-context $USER --cluster=$(kubectl config current-context) --user=$USER