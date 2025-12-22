package client_test

import (
	"net"
	"os"
	"strings"
)

type HostPort struct {
	Host string
	Port string
}

func (hp *HostPort) String() string {
	return net.JoinHostPort(hp.Host, hp.Port)
}

type EnvConfig struct {
	Addr5, Addr5Pass, Addr4, Addr4Pass string
	Pairs                              []HostPort // example.com:http|google.com:http
	RCTimeout                          int
}

func GetEnvConfig() EnvConfig {
	ret := EnvConfig{
		Addr5:     "127.0.0.1:1096",
		Addr5Pass: "127.0.0.1:1097",
		Addr4:     "127.0.0.1:1098",
		Addr4Pass: "127.0.0.1:1099",

		Pairs: []HostPort{
			{"example.com", "http"},
			{"google.com", "http"},
		},

		RCTimeout: 2000,
	}

	// TODO: Parse RCTimeout

	addr5 := os.Getenv("SOCKS_TEST_ADDR5")
	if addr5 != "" {
		ret.Addr5 = addr5
	}

	addr5pass := os.Getenv("SOCKS_TEST_ADDR5PASS")
	if addr5pass != "" {
		ret.Addr5Pass = addr5pass
	}

	addr4 := os.Getenv("SOCKS_TEST_ADDR4")
	if addr4 != "" {
		ret.Addr4 = addr4
	}

	pairsStr := os.Getenv("SOCKS_TEST_PAIRS")
	if pairsStr != "" {
		pairs := []HostPort{}
		for pair := range strings.SplitSeq(pairsStr, "|") {
			host, port, err := net.SplitHostPort(strings.TrimSpace(pair))
			if err != nil {
				continue
			}
			pairs = append(pairs, HostPort{
				Host: host,
				Port: port,
			})
		}
	}

	return ret
}
