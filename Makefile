.PHONY: build test lint validate-errors clean

# Build the main binary
build:
	go build -o bin/erst ./cmd/erst

# Run tests
test:
	go test ./...

# Run full linter suite
lint:
	golangci-lint run

# Validate error standardization
validate-errors:
	./scripts/validate-errors.sh

# Clean build artifacts
clean:
	rm -rf bin/
	go clean -cache

# Install dependencies
deps:
	go mod tidy
	go mod download
