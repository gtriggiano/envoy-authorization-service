GO ?= go
DOCKER ?= docker
BINARY ?= envoy-authorization-service
BUILD_DIR ?= bin
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
LDFLAGS ?=
RELEASE_BUMP ?= auto
POSTGRES_USER ?= postgres
POSTGRES_PASSWORD ?= postgres

.PHONY: all build build-all clean test test-e2e tidy run run-redis run-postgres fetch-maxmind seed-postgres seed-redis fmt docker release compose-up compose-down

all: clean tidy fmt test build-all

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
	$(GO) test -cover ./...

test-e2e: fetch-maxmind
	@mkdir -p .cache/go-build .cache/go-tmp
	$(DOCKER) info >/dev/null
	GOCACHE=$(PWD)/.cache/go-build GOTMPDIR=$(PWD)/.cache/go-tmp $(GO) test -cover -tags=e2e ./...

test-all: fetch-maxmind
	@mkdir -p .cache/go-build .cache/go-tmp
	@echo "Running all tests (non-e2e + e2e) with coverage..."
	@which gocovmerge > /dev/null || $(GO) install github.com/wadey/gocovmerge@latest
	@GOCACHE=$(PWD)/.cache/go-build GOTMPDIR=$(PWD)/.cache/go-tmp $(GO) test -covermode=atomic -coverprofile=coverage-e2e.out -tags=e2e ./... 2>&1 | grep -v "no test files" || true
	@GOCACHE=$(PWD)/.cache/go-build GOTMPDIR=$(PWD)/.cache/go-tmp $(GO) test -covermode=atomic -coverprofile=coverage-regular.out ./... 2>&1 | grep -v "no test files" || true
	@gocovmerge coverage-e2e.out coverage-regular.out > coverage.out
	@$(GO) tool cover -func=coverage.out | tee coverage.txt
	@rm -f coverage-e2e.out coverage-regular.out
	@echo ""
	@echo "Total coverage: $$(awk '/^total:/{print $$3}' coverage.txt)"

tidy:
	$(GO) mod tidy

run-ip-match: fetch-maxmind
	$(GO) run . start --config config/config.ip-match.yaml

run-redis: fetch-maxmind compose-up seed-redis
	$(GO) run . start --config config/config.redis.yaml

run-postgres: fetch-maxmind compose-up seed-postgres
	POSTGRES_USER=$(POSTGRES_USER) POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) $(GO) run . start --config config/config.postgres.yaml

seed-databases: seed-postgres seed-redis

seed-postgres: compose-up
	@echo "Waiting for Postgres to be ready..."
	@for i in $$(seq 1 30); do \
		$(DOCKER) compose exec -T postgres pg_isready -U postgres -d security >/dev/null 2>&1 && break; \
		echo "  postgres not ready yet... ($$i/30)"; \
		sleep 1; \
	done
	@echo "Seeding Postgres database..."
	$(DOCKER) compose exec -T postgres psql -U postgres -d security -f /seed.sql

seed-redis: compose-up
	@echo "Waiting for Redis to be ready..."
	@for i in $$(seq 1 30); do \
		$(DOCKER) compose exec redis redis-cli ping >/dev/null 2>&1 && break; \
		echo "  redis not ready yet... ($$i/30)"; \
		sleep 1; \
	done
	$(DOCKER) compose exec redis redis-cli set trusted:203.0.113.10 1
	$(DOCKER) compose exec redis redis-cli set scraper:211.0.27.6 1

fetch-maxmind:
	@./scripts/fetch-maxmind.sh

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

release: clean tidy fmt test build-all
	@./scripts/release.sh $(RELEASE_BUMP)

docker:
	docker build -t $(BINARY):dev .

compose-up:
	$(DOCKER) compose up -d

compose-down:
	$(DOCKER) compose down
