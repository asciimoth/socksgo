set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := true

typos:
  typos

check: tidy typos fmt lint vet test fuzz test-e2e

test:
  go test ./... -tags=testhooks --race -count=1

fuzz:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "Skipping fuzzing in GitHub Actions."
    exit 0
  fi
  go test . \
    -run='^$' \
    -fuzz='^FuzzUntrustedInput$' \
    -fuzztime="${FUZZ_TIME:-1m}"

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
