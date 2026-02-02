package internal_test

import (
	"os"
	"testing"

	"github.com/asciimoth/socksgo/internal"
)

func TestGetProxyFromEnvVar(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		env      map[string]string
		expected string
	}{
		// Empty scheme cases
		{
			name:     "empty scheme, no env vars",
			scheme:   "",
			env:      nil,
			expected: "",
		},
		{
			name:   "empty scheme, only SOCKS_PROXY",
			scheme: "",
			env: map[string]string{
				"SOCKS_PROXY": "socks5://proxy:1080",
			},
			expected: "socks5://proxy:1080",
		},
		{
			name:   "empty scheme, only socks_proxy",
			scheme: "",
			env: map[string]string{
				"socks_proxy": "socks5://proxy:1080",
			},
			expected: "socks5://proxy:1080",
		},
		{
			name:   "empty scheme, SOCKS_PROXY takes precedence over all_proxy",
			scheme: "",
			env: map[string]string{
				"all_proxy":   "http://fallback:8080",
				"SOCKS_PROXY": "socks5://primary:1080",
			},
			expected: "socks5://primary:1080",
		},
		{
			name:   "empty scheme, ALL_PROXY fallback",
			scheme: "",
			env: map[string]string{
				"ALL_PROXY": "http://fallback:8080",
			},
			expected: "http://fallback:8080",
		},
		{
			name:   "empty scheme, all_proxy fallback",
			scheme: "",
			env: map[string]string{
				"all_proxy": "http://fallback:8080",
			},
			expected: "http://fallback:8080",
		},

		// With scheme cases
		{
			name:     "with scheme, no env vars",
			scheme:   "http",
			env:      nil,
			expected: "",
		},
		{
			name:   "with scheme, uppercase scheme priority",
			scheme: "http",
			env: map[string]string{
				"HTTP_PROXY": "http://proxy:8080",
				"ALL_PROXY":  "http://fallback:8080",
			},
			expected: "http://proxy:8080",
		},
		{
			name:   "with scheme, lowercase scheme priority",
			scheme: "https",
			env: map[string]string{
				"https_proxy": "https://proxy:443",
				"ALL_PROXY":   "http://fallback:8080",
			},
			expected: "https://proxy:443",
		},
		{
			name:   "with scheme, scheme uppercase before lowercase",
			scheme: "ftp",
			env: map[string]string{
				"ftp_proxy": "ftp://proxy:21",
				"FTP_PROXY": "ftp://primary:21",
			},
			expected: "ftp://primary:21",
		},
		{
			name:   "with scheme, fallback to ALL_PROXY",
			scheme: "http",
			env: map[string]string{
				"ALL_PROXY": "socks5://fallback:1080",
			},
			expected: "socks5://fallback:1080",
		},
		{
			name:   "with scheme, fallback to all_proxy",
			scheme: "https",
			env: map[string]string{
				"all_proxy": "http://fallback:8080",
			},
			expected: "http://fallback:8080",
		},

		// Edge cases
		{
			name:   "scheme with spaces",
			scheme: "  http  ",
			env: map[string]string{
				"HTTP_PROXY": "http://proxy:8080",
			},
			expected: "http://proxy:8080",
		},
		{
			name:   "env value with spaces",
			scheme: "http",
			env: map[string]string{
				"HTTP_PROXY": "  http://proxy:8080  ",
			},
			expected: "http://proxy:8080",
		},
		{
			name:   "empty env value ignored",
			scheme: "http",
			env: map[string]string{
				"HTTP_PROXY": "",
				"ALL_PROXY":  "http://fallback:8080",
			},
			expected: "http://fallback:8080",
		},
		{
			name:   "mixed case scheme",
			scheme: "HtTp",
			env: map[string]string{
				"HTTP_PROXY": "http://proxy:8080",
			},
			expected: "http://proxy:8080",
		},
		{
			name:   "non-alphanumeric scheme",
			scheme: "http+s",
			env: map[string]string{
				"HTTP+S_PROXY": "https://proxy:443",
			},
			expected: "https://proxy:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Backup and restore environment
			oldEnv := make(map[string]string)
			for k, v := range tt.env {
				if old, exists := os.LookupEnv(k); exists {
					oldEnv[k] = old
				}
				_ = os.Setenv(k, v) //nolint
			}
			defer func() {
				for k := range tt.env {
					if old, exists := oldEnv[k]; exists {
						_ = os.Setenv(k, old) //nolint
					} else {
						_ = os.Unsetenv(k)
					}
				}
			}()

			// Clear any unrelated proxy env vars
			allProxyVars := []string{
				"SOCKS_PROXY", "socks_proxy",
				"HTTP_PROXY", "http_proxy",
				"HTTPS_PROXY", "https_proxy",
				"FTP_PROXY", "ftp_proxy",
				"ALL_PROXY", "all_proxy",
			}
			for _, v := range allProxyVars {
				if _, exists := tt.env[v]; !exists {
					_ = os.Unsetenv(v)
				}
			}

			result := internal.GetProxyFromEnvVar(tt.scheme)
			if result != tt.expected {
				t.Errorf(
					"GetProxyFromEnvVar(%q) = %q, want %q",
					tt.scheme,
					result,
					tt.expected,
				)
			}
		})
	}
}
