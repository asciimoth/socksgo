set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

typos:
  typos

check: tidy typos fmt lint vet test test-e2e

test:
  go test ./... -tags=testhooks --race -count=1

test-e2e:
  ./scripts/run_e2e.sh go test ./... -tags="compattest testhooks" --race -count=1

vet:
	go vet ./...

tidy:
	go mod tidy

lint:
  golangci-lint run ./...

fmt:
  golangci-lint fmt ./...
