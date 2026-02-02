package internal

import (
	"os"
	"strings"
)

func GetProxyFromEnvVar(scheme string) (val string) {
	prior := []string{"ALL_PROXY", "all_proxy"}
	if scheme == "" {
		prior = append([]string{"SOCKS_PROXY", "socks_proxy"}, prior...)
	} else {
		scheme = strings.TrimSpace(scheme)
		prior = append([]string{
			strings.ToUpper(scheme) + "_PROXY",
			strings.ToLower(scheme) + "_proxy",
		}, prior...)
	}
	for _, key := range prior {
		val = os.Getenv(key)
		if val != "" {
			break
		}
	}
	if val != "" {
		val = strings.TrimSpace(val)
	}
	return
}
