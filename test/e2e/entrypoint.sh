#!/bin/sh
set -eu

tor_data_dir="$(mktemp -d)"
tor_log="$(mktemp)"
tor_pid=""

cleanup() {
	if [ -n "${tor_pid}" ]; then
		kill "${tor_pid}" 2>/dev/null || true
		wait "${tor_pid}" 2>/dev/null || true
	fi
	rm -rf "${tor_data_dir}"
	rm -f "${tor_log}"
}
trap cleanup EXIT INT TERM

tor -f /usr/local/etc/socksgo-torrc \
	--DataDirectory "${tor_data_dir}" \
	--Log "notice file ${tor_log}" &
tor_pid=$!

attempt=0
while ! grep -q "Bootstrapped 100%" "${tor_log}"; do
	if ! kill -0 "${tor_pid}" 2>/dev/null; then
		echo "Tor stopped before it was ready." >&2
		cat "${tor_log}" >&2
		exit 1
	fi
	if [ "${attempt}" -ge 120 ]; then
		echo "Tor did not become ready in 120 seconds." >&2
		cat "${tor_log}" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	sleep 1
done

"$@"
