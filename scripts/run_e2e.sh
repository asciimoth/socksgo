#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_file="$(mktemp)"
container_id=""

cleanup() {
	if [[ -n "${container_id}" ]]; then
		docker rm --force "${container_id}" >/dev/null 2>&1 || true
	fi
	rm -f "${image_file}"
}
trap cleanup EXIT

docker build \
	--file "${project_dir}/test/e2e/Dockerfile" \
	--iidfile "${image_file}" \
	"${project_dir}"
image_id="$(<"${image_file}")"

coverage_file="${SOCKSGO_E2E_COVERAGE_FILE:-}"
if [[ -n "${coverage_file}" ]]; then
	if [[ $# -ne 0 ]]; then
		echo "Do not give test arguments with SOCKSGO_E2E_COVERAGE_FILE." >&2
		exit 2
	fi

	container_id="$(docker create --network bridge "${image_id}" \
		go test ./... \
		'-tags=compattest testhooks' \
		-count=1 \
		-coverprofile=/tmp/coverage.out \
		-coverpkg=./...)"

	test_status=0
	docker start --attach "${container_id}" || test_status=$?
	if [[ ${test_status} -eq 0 ]]; then
		docker cp \
			"${container_id}:/tmp/coverage.out" \
			"${project_dir}/${coverage_file}"
	fi
	exit "${test_status}"
fi

if [[ $# -eq 0 ]]; then
	docker run --rm --network bridge "${image_id}"
else
	docker run --rm --network bridge "${image_id}" "$@"
fi
