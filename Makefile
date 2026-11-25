BINARY  := my-auth-go
VERSION ?= 1.0.0
DIST    := dist
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build release test vet fmt swagger seed clean install

all: build

## build    : binary untuk mesin ini
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/api
	@ls -lh $(BINARY)

## release  : cross-compile linux amd64 + arm64 ke dist/ + SHA256SUMS
release: test vet
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/my-auth-go-linux-amd64 ./cmd/api
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/my-auth-go-linux-arm64 ./cmd/api
	@cd $(DIST) && sha256sum my-auth-go-linux-* > SHA256SUMS
	@ls -lh $(DIST)/

test:
	go test ./tests/... -v

vet:
	go vet ./...

fmt:
	gofmt -l -w .

## seed     : migrasi + seeder admin (butuh .env / environment terisi)
seed: build
	./$(BINARY) --seed

## install  : pasang ke /usr/local/bin (butuh root)
install: release
	install -o root -g root -m 0755 $(DIST)/my-auth-go-linux-amd64 /usr/local/bin/my-auth-go

clean:
	rm -rf $(BINARY) $(DIST)
