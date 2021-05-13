FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/open-cluster-management/api-network-proxy-addon
COPY . .
# TODO use go build command to build user-server
RUN make build user-server

FROM scratch
WORKDIR /
COPY --from=builder /go/src/github.com/open-cluster-management/api-network-proxy-addon/user-server .
ENTRYPOINT ["/user-server"]