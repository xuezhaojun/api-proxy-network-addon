# create service account
kubectl create serviceaccount jenkins

kubectl get serviceaccounts jenkins -o yaml

kubectl get secret jenkins-token-1yvwg -o yaml

# bind service account wit role