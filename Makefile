APP := pgp-client
CLI := pgp-client-cli
FYNE := go run fyne.io/tools/cmd/fyne@v1.7.2

.PHONY: all fmt test test-race vet build build-desktop build-cli build-ci run package clean

all: test vet build

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

test:
	go test -tags ci ./...

test-race:
	go test -race -tags ci ./...

vet:
	go vet -tags ci ./...

build: build-desktop build-cli

build-desktop:
	mkdir -p bin
	go build -trimpath -o bin/$(APP) ./cmd/pgp-client

build-cli:
	mkdir -p bin
	go build -trimpath -o bin/$(CLI) ./cmd/pgp-client-cli

build-ci:
	mkdir -p bin
	go build -trimpath -tags ci -o bin/$(APP)-ci ./cmd/pgp-client
	go build -trimpath -o bin/$(CLI) ./cmd/pgp-client-cli

run:
	go run ./cmd/pgp-client

package:
	$(FYNE) package --src ./cmd/pgp-client

clean:
	rm -rf bin dist build coverage.out
