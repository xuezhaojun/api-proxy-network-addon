kubectl config use-context kind-hub
kubectl delete -f scripts/test/hub.yaml

kubectl config use-context kind-spoke1
kubectl delete -f scripts/test/spoke1.yaml
kubectl delete -f scripts/test/add-admin-role.yaml

kubectl config use-context kind-spoke2
kubectl delete -f scripts/test/spoke2.yaml
kubectl delete -f scripts/test/add-admin-role.yaml

