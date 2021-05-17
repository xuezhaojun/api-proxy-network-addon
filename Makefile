DOCKER_CMD ?= docker
ARCH ?= amd64
USER_SERVER_IMAGE ?= userserver
KUBECTL_PROXY_IMANGE ?= kubectlproxy
TAG ?= 1.0.1

.PHONY: docker-build/user-server
docker-build/user-server: cmd/user-server/main.go
	echo "Building user-server for ${ARCH}"
	${DOCKER_CMD} build -f Dockerfiles/user-server.Dockerfile -t ${USER_SERVER_IMAGE}:${TAG} .

.PHONY: docker-build/kubectl-proxy
docker-build/kubectl-proxy:
	echo "Building kubectl-proxy for ${ARCH}"
	${DOCKER_CMD} build -f Dockerfiles/kubectl-proxy.Dockerfile -t ${KUBECTL_PROXY_IMANGE}:${TAG} .