// nolint
package socksgo_test

import (
	"testing"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/loopback"
	gt "github.com/asciimoth/gonnect/testing"
	"github.com/asciimoth/socksgo"
)

func newNetwork() gt.Network {
	loop := loopback.NewLoopbackNetwok()
	client := &socksgo.Client{
		Filter: gonnect.FalseFilter,
	}
	client.WithNetwork(loop)
	return &socksgo.GonnectClient{
		Client: client,
	}
}

func TestNativeNetworkTcpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: newNetwork(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunTcpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetworkHTTP(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: newNetwork(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunSimpleHTTPForNetworks(t, pair, pair)
}

func TestNativeNetworkUdpPingPong(t *testing.T) {
	pair := gt.NetAddrPair{
		Network: newNetwork(),
		Addr:    "127.0.0.1:0",
	}
	gt.RunUdpPingPongForNetworks(t, pair, pair)
}

func TestNativeNetwork_Compliance(t *testing.T) {
	gt.RunNetworkErrorComplianceTests(t, func() gt.Network {
		return newNetwork()
	})
}
