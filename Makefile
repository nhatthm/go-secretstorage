MODULE_NAME=secretstorage

VENDOR_DIR = vendor

GOLANGCI_LINT_VERSION ?= v1.61.0
MOCKERY_VERSION ?= v2.46.3

GO ?= go
GOLANGCI_LINT ?= $(shell go env GOPATH)/bin/golangci-lint-$(GOLANGCI_LINT_VERSION)
MOCKERY ?= $(shell go env GOPATH)/bin/mockery-$(MOCKERY_VERSION)

.PHONY: $(VENDOR_DIR)
$(VENDOR_DIR):
	@mkdir -p $(VENDOR_DIR)
	@$(GO) mod vendor
	@$(GO) mod tidy

.PHONY: generate
generate: $(MOCKERY)
	@echo ">> generate mocks"
	@$(MOCKERY)

.PHONY: lint
lint: $(GOLANGCI_LINT)
	@$(GOLANGCI_LINT) run

.PHONY: test
test: test-unit

## Run unit tests
.PHONY: test-unit
test-unit:
	@echo ">> unit test"
	@$(GO) test -gcflags=-l -coverprofile=unit.coverprofile -covermode=atomic -race ./...

#.PHONY: test-integration
#test-integration:
#	@echo ">> integration test"
#	@$(GO) test -gcflags=-l -coverprofile=integration.coverprofile -covermode=atomic -race -tags=integration ./...

.PHONY: $(GITHUB_ENV)
$(GITHUB_ENV):
	@echo "MODULE_NAME=$(MODULE_NAME)" >>"$@"
	@echo "GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION)" >>"$@"

.PHONY: $(GITHUB_OUTPUT)
$(GITHUB_OUTPUT):
	@echo "MODULE_NAME=$(MODULE_NAME)" >>"$@"
	@echo "GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION)" >>"$@"

$(GOLANGCI_LINT):
	@echo "$(OK_COLOR)==> Installing golangci-lint $(GOLANGCI_LINT_VERSION)$(NO_COLOR)"; \
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b ./bin "$(GOLANGCI_LINT_VERSION)"
	@mv ./bin/golangci-lint $(GOLANGCI_LINT)

$(MOCKERY):
	@echo "$(OK_COLOR)==> Installing mockery $(MOCKERY_VERSION)$(NO_COLOR)"; \
	GOBIN=/tmp $(GO) install github.com/vektra/mockery/$(shell echo "$(MOCKERY_VERSION)" | cut -d '.' -f 1)@$(MOCKERY_VERSION)
	@mv /tmp/mockery $(MOCKERY)
