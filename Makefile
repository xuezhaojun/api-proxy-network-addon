
DOCKER_CMD ?= docker
ARCH ?= amd64
USER_SERVER_FULL_IMAGE ?= userserver
TAG ?= 1.0.0

.PHONY: docker-build/user-server
docker-build/user-server: cmd/user-server/main.go
	echo "Building user-server for ${ARCH}"
	${DOCKER_CMD} build . --build-arg ARCH=$(ARCH) -f Dockerfiles/user-server.Dockerfile -t ${USER_SERVER_FULL_IMAGE}-$(ARCH):${TAG}


