# syntax=docker/dockerfile:1.6

ARG GO_IMAGE=golang:1.25

FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -ldflags="-s -w" -o /out/envoy-authorization-service .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/envoy-authorization-service /usr/local/bin/envoy-authorization-service
ENTRYPOINT ["/usr/local/bin/envoy-authorization-service"]
CMD ["start", "--config", "/config/config.yaml"]
