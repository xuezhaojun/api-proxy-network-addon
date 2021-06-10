kubectl config use-context kind-hub
kubectl apply -f scripts/test/hub.yaml

kubectl config use-context kind-cluster1
kubectl apply -f scripts/test/cluster1.yaml
kubectl apply -f scripts/test/add-admin-role.yaml

kubectl config use-context kind-cluster2
kubectl apply -f scripts/test/cluster2.yaml
kubectl apply -f scripts/test/add-admin-role.yaml