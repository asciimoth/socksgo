package socks_test

import (
	"testing"

	"github.com/asciimoth/socks"
)

func TestClientFromURL(t *testing.T) {
	tests := []struct {
		Name string

		Url string

		Version               string
		GetAddr               string
		IsTLS                 bool
		IsUDPAllowed           bool
		TLSInsecureSkipVerify bool
		WebSocketURL          string
	}{
		{
			Name:        "Standard socks5",
			Url:         "socks5://127.0.0.1:8080",
			Version:     "5",
			GetAddr:     "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:        "Standard socks5h",
			Url:         "socks5h://127.0.0.1:8080",
			Version:     "5",
			GetAddr:     "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:        "Standard socks4",
			Url:         "socks4://127.0.0.1:8080",
			Version:     "4",
			GetAddr:     "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:        "Standard socks4a",
			Url:         "socks4a://127.0.0.1:8080",
			Version:     "4a",
			GetAddr:     "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:                  "socks5+tls",
			Url:                   "socks5+tls://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:           false,
			IsTLS:                 true,
			TLSInsecureSkipVerify: true,
		},
		{
			Name:                  "socks5+tls+secure",
			Url:                   "socks5+tls://127.0.0.1:8080?secure",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:           false,
			IsTLS:                 true,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+ws",
			Url:                   "socks5+ws://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:           true,
			WebSocketURL:          "ws://127.0.0.1:8080/ws",
			IsTLS:                 false,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+ws+path",
			Url:                   "socks5+ws://127.0.0.1:8080/custom/path",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:           true,
			WebSocketURL:          "ws://127.0.0.1:8080/custom/path",
			IsTLS:                 false,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+wss",
			Url:                   "socks5+wss://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:           false,
			WebSocketURL:          "wss://127.0.0.1:8080/ws",
			IsTLS:                 true,
			TLSInsecureSkipVerify: true,
		},
		{
			Name:                  "socks5+wss+secure",
			Url:                   "socks5+wss://127.0.0.1:8080?secure",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:           false,
			WebSocketURL:          "wss://127.0.0.1:8080/ws",
			IsTLS:                 true,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+ws+tls",
			Url:                   "socks5+ws+tls://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:           false,
			WebSocketURL:          "wss://127.0.0.1:8080/ws",
			IsTLS:                 true,
			TLSInsecureSkipVerify: true,
		},
		{
			Name:        "Default port",
			Url:         "socks5://127.0.0.1",
			Version:     "5",
			GetAddr:     "127.0.0.1:1080",
			IsUDPAllowed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			client, err := socks.ClientFromURL(tc.Url)
			if err != nil {
				t.Errorf("unexpected error %v", err)
				return
			}

			if client.Version() != tc.Version {
				t.Errorf("Version() == %s while expected %s", client.Version(), tc.Version)
			}
			if client.GetAddr() != tc.GetAddr {
				t.Errorf("GetAddr() == %s while expected %s", client.GetAddr(), tc.GetAddr)
			}
			if client.WebSocketURL != tc.WebSocketURL {
				t.Errorf("WebSocketURL() == %s while expected %s", client.WebSocketURL, tc.WebSocketURL)
			}
			if client.IsTLS() != tc.IsTLS {
				t.Errorf("IsTLS() == %t while expected %t", client.IsTLS(), tc.IsTLS)
			}
			if client.IsUDPAllowed() != tc.IsUDPAllowed {
				t.Errorf("IsUDPAllowed() == %t while expected %t", client.IsUDPAllowed(), tc.IsUDPAllowed)
			}

			if tc.IsTLS {
				TLSInsecureSkipVerify := false
				if client.TLSConfig != nil {
					TLSInsecureSkipVerify = client.TLSConfig.InsecureSkipVerify
				}
				if TLSInsecureSkipVerify != tc.TLSInsecureSkipVerify {
					t.Errorf(
						"TLSInsecureSkipVerify() == %t while expected %t",
						TLSInsecureSkipVerify,
						tc.TLSInsecureSkipVerify,
					)
				}
			}
		})
	}
}
