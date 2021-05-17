kubectl config use-context kind-hub
kubectl apply -f scripts/test/hub.yaml

kubectl config use-context kind-spoke1
kubectl apply -f scripts/test/spoke1.yaml
kubectl apply -f scripts/test/admin_role.yaml

kubectl config use-context kind-spoke2
kubectl apply -f scripts/test/spoke2.yaml
kubectl apply -f scripts/test/admin_role.yaml