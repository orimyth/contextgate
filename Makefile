VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: build clean test run

build:
	go build -ldflags "-X main.version=$(VERSION)" -o contextgate .

clean:
	rm -f contextgate

test:
	go test ./...

run: build
	@echo "Usage: ./contextgate [--dashboard :9000] -- <command> [args...]"
