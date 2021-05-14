FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/open-cluster-management/api-network-proxy-addon

COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -o user-server ./cmd/user-server

FROM scratch
WORKDIR /
COPY --from=builder /go/src/github.com/open-cluster-management/api-network-proxy-addon/user-server .
ENTRYPOINT ["/user-server"]