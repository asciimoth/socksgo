// nolint
package socksgo_test

import (
	"context"
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

// Test GonnectClient methods
func TestGonnectClient_LookupPort(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
	}
	gc := &socksgo.GonnectClient{Client: client}

	ctx := context.Background()
	_, err := gc.LookupPort(ctx, "tcp", "http")
	if err != nil {
		t.Fatalf("LookupPort failed: %v", err)
	}
}

func TestGonnectClient_InterfaceMethods(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
	}
	gc := &socksgo.GonnectClient{Client: client}

	// Test Interfaces
	interfaces, err := gc.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces failed: %v", err)
	}
	if len(interfaces) != 0 {
		t.Fatalf("expected empty interfaces slice, got %d", len(interfaces))
	}

	// Test InterfaceAddrs
	addrs, err := gc.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs failed: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("expected empty addrs slice, got %d", len(addrs))
	}

	// Test InterfacesByIndex
	_, err = gc.InterfacesByIndex(1)
	if err == nil {
		t.Fatal("expected error for InterfacesByIndex")
	}

	// Test InterfacesByName
	_, err = gc.InterfacesByName("eth0")
	if err == nil {
		t.Fatal("expected error for InterfacesByName")
	}
}

func TestGonnectClient_DNSMethods(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
	}
	gc := &socksgo.GonnectClient{Client: client}

	ctx := context.Background()

	// Test LookupCNAME
	_, err := gc.LookupCNAME(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for LookupCNAME")
	}

	// Test LookupNS
	_, err = gc.LookupNS(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for LookupNS")
	}

	// Test LookupMX
	_, err = gc.LookupMX(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for LookupMX")
	}

	// Test LookupSRV
	_, _, err = gc.LookupSRV(ctx, "http", "tcp", "example.com")
	if err == nil {
		t.Fatal("expected error for LookupSRV")
	}

	// Test LookupTXT
	_, err = gc.LookupTXT(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for LookupTXT")
	}
}
