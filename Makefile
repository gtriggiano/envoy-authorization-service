GO ?= go
BINARY ?= envoy-authorization-service
BUILD_DIR ?= bin
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
LDFLAGS ?=
DOCKER_IMAGE ?= gtriggiano/$(BINARY)

.PHONY: all build build-all clean test tidy run fmt docker

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@GOOS=$$(go env GOOS); \
	GOARCH=$$(go env GOARCH); \
	out="$(BUILD_DIR)/$(BINARY)"; \
	echo "Building $$out"; \
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" .

build-all:
	@mkdir -p $(BUILD_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		out="$(BUILD_DIR)/$(BINARY)-$$os-$$arch"; \
		echo "Building $$out"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" . || exit 1; \
	done

clean:
	rm -rf $(BUILD_DIR)

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

run:
	$(GO) run . start --config config/config.example.yaml

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

