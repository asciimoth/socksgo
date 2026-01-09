package socks

import (
	"slices"
	"strings"
)

func checkURLBoolKey(values map[string][]string, key string) (f bool, s bool) {
	val, ok := values[key]
	if ok {
		if len(val) == 0 {
			return true, true
		}
		v := val[0]
		return v == "true" || v == "yes" || v == "ok" || v == "1" || v == "", true
	}
	return false, false
}

// base = "4" | "4a" | "5"
func parseScheme(scheme string) (base string, tls, ws bool) {
	parts := strings.Split(strings.TrimSpace(strings.ToLower(scheme)), "+")
	for _, p := range []string{"socks", "socks5", "socks5h"} {
		if slices.Contains(parts, p) {
			base = "5"
		}
	}
	for _, p := range []string{"sockss", "socks5s", "socks5hs"} {
		if slices.Contains(parts, p) {
			base = "5"
			tls = true
		}
	}
	if slices.Contains(parts, "socks4") {
		base = "4"
	}
	if slices.Contains(parts, "socks4s") {
		base = "4"
		tls = true
	}
	if slices.Contains(parts, "socks4a") {
		base = "4a"
	}
	if slices.Contains(parts, "socks4as") {
		base = "4a"
		tls = true
	}
	if slices.Contains(parts, "tls") {
		tls = true
	}
	if slices.Contains(parts, "ws") {
		ws = true
	}
	if slices.Contains(parts, "wss") {
		ws = true
		tls = true
	}
	return
}
