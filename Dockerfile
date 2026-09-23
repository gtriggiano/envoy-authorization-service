# syntax=docker/dockerfile:1

ARG GO_IMAGE=golang:1.27

# Build identity: also stamped into the binary (see `envoy-authorization-service version`).
ARG VERSION=dev
ARG REVISION=
ARG CREATED=

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG REVISION
ARG CREATED
WORKDIR /src

RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=bind,source=go.mod,target=go.mod \
	--mount=type=bind,source=go.sum,target=go.sum \
	go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath \
	-ldflags="-s -w \
	-X github.com/gtriggiano/envoy-authorization-service/pkg/version.Version=${VERSION} \
	-X github.com/gtriggiano/envoy-authorization-service/pkg/version.Commit=${REVISION} \
	-X github.com/gtriggiano/envoy-authorization-service/pkg/version.BuildDate=${CREATED}" \
	-o /out/envoy-authorization-service .

# Fail the build when the version was not stamped (a cross-compiled binary cannot run here, so skip then).
RUN if [ "${TARGETOS}/${TARGETARCH}" = "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" ]; then \
	got="$(/out/envoy-authorization-service version --output short)"; \
	[ "$got" = "${VERSION}" ] || { echo "version stamping failed: got '$got', want '${VERSION}'" >&2; exit 1; }; \
	fi

FROM gcr.io/distroless/static:nonroot

ARG VERSION
ARG REVISION
ARG CREATED

LABEL org.opencontainers.image.title="envoy-authorization-service" \
	org.opencontainers.image.description="External authorization service implementing the Envoy ext_authz gRPC API" \
	org.opencontainers.image.source="https://github.com/gtriggiano/envoy-authorization-service" \
	org.opencontainers.image.url="https://gtriggiano.github.io/envoy-authorization-service/" \
	org.opencontainers.image.documentation="https://gtriggiano.github.io/envoy-authorization-service/" \
	org.opencontainers.image.licenses="MIT" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${REVISION}" \
	org.opencontainers.image.created="${CREATED}"

COPY --from=builder /out/envoy-authorization-service /usr/local/bin/envoy-authorization-service

# gRPC ext_authz listener and metrics/health HTTP server (defaults; configurable)
EXPOSE 9001 9090

ENTRYPOINT ["/usr/local/bin/envoy-authorization-service"]
CMD ["start", "--config", "/config/config.yaml"]
