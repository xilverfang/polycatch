.PHONY: build run clean test install deps help

# Application name
APP_NAME := polywatch
BINARY := ./$(APP_NAME)

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOFMT := $(GOCMD) fmt

# Build flags
LDFLAGS := -s -w
BUILD_FLAGS := -ldflags "$(LDFLAGS)"

# Main package path
MAIN_PKG := ./cmd/polywatch

# Default target
.DEFAULT_GOAL := help

## build: Build the application binary to ./polywatch
build:
	@echo "Building $(APP_NAME)..."
	$(GOBUILD) $(BUILD_FLAGS) -o $(BINARY) $(MAIN_PKG)
	@echo "Build complete: $(BINARY)"
	@echo ""
	@echo "Usage:"
	@echo "  ./polywatch --telegram        # Run Telegram bot"
	@echo "  ./polywatch --monitor         # Run CLI monitor"
	@echo "  ./polywatch --executor        # Run CLI executor"
	@echo "  ./polywatch --create-api-key  # Generate API credentials"

## run: Run the application (shows usage)
run:
	@echo "Running $(APP_NAME)..."
	$(GOCMD) run $(MAIN_PKG)

## run-telegram: Run the Telegram bot
run-telegram:
	@echo "Running Telegram bot..."
	$(GOCMD) run $(MAIN_PKG) --telegram

## run-monitor: Run the CLI monitor
run-monitor:
	@echo "Running CLI monitor..."
	$(GOCMD) run $(MAIN_PKG) --monitor

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(APP_NAME)
	@rm -rf bin/ data/
	@rm -f *.db *.db-wal *.db-shm
	@echo "Clean complete"

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## fmt: Format all Go code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...
	@echo "Format complete"

## deps: Download and tidy dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies updated"

## install: Install the binary to GOPATH/bin
install: build
	@echo "Installing $(APP_NAME)..."
	$(GOCMD) install $(MAIN_PKG)
	@echo "Install complete"

## lint: Run golangci-lint (if installed)
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running linter..."; \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## help: Show this help message
help:
	@echo "Available targets:"
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //' | awk -F: '{printf "  %-20s %s\n", $$1, $$2}'

