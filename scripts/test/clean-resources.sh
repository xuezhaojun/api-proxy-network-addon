kubectl config use-context kind-hub
kubectl delete -f scripts/test/hub.yaml

kubectl config use-context kind-cluster1
kubectl delete -f scripts/test/cluster1.yaml
kubectl delete -f scripts/test/add-admin-role.yaml

kubectl config use-context kind-cluster2
kubectl delete -f scripts/test/cluster2.yaml
kubectl delete -f scripts/test/add-admin-role.yaml

