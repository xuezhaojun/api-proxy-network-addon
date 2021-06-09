kind create cluster --config=./scripts/test/kind-hub.yaml --name=hub
kind create cluster --name=spoke1
kind create cluster --name=spoke2