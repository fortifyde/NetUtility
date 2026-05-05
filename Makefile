VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build lint test clean

build:
	go build $(LDFLAGS) -o netutil ./cmd/netutil
	go build $(LDFLAGS) -o bin/ouihelper ./cmd/ouihelper
	go build $(LDFLAGS) -o bin/netutil-fileserver ./cmd/fileserver

lint:
	golangci-lint run ./...

test:
	go test -v -race ./...

clean:
	rm -f netutil bin/ouihelper bin/netutil-fileserver
