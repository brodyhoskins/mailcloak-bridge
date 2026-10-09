.PHONY: build test docker roots

VERSION ?= $(shell cat VERSION)
LDFLAGS := $(if $(VERSION),-X github.com/brodyhoskins/mailcloak-bridge/internal/version.Version=$(VERSION))

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o . ./cmd/...

test:
	go test ./...

docker:
	docker build --build-arg VERSION=$(VERSION) -t mailcloak-bridge:$(VERSION) .

# Mozilla's roots trusted for email, embedded for S/MIME signature checks.
roots:
	curl -sSfL -o internal/cloak/emailroots.pem 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Email'
