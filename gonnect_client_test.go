// nolint
package socksgo_test

import (
	"context"
	"testing"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo"
)

func TestGonnectClient_Resolver(t *testing.T) {
	t.Parallel()

	client := &socksgo.GonnectClient{Client: &socksgo.Client{}}
	ctx := context.Background()

	t.Run("LookupCNAME", func(t *testing.T) {
		t.Parallel()
		cname, err := client.LookupCNAME(ctx, "example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if cname != "" {
			t.Errorf("expected empty CNAME, got %q", cname)
		}
	})

	t.Run("LookupNS", func(t *testing.T) {
		t.Parallel()
		ns, err := client.LookupNS(ctx, "example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if ns != nil {
			t.Errorf("expected nil NS records, got %v", ns)
		}
	})

	t.Run("LookupMX", func(t *testing.T) {
		t.Parallel()
		mx, err := client.LookupMX(ctx, "example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if mx != nil {
			t.Errorf("expected nil MX records, got %v", mx)
		}
	})

	t.Run("LookupSRV", func(t *testing.T) {
		t.Parallel()
		target, srv, err := client.LookupSRV(ctx, "http", "tcp", "example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if target != "" {
			t.Errorf("expected empty target, got %q", target)
		}
		if srv != nil {
			t.Errorf("expected nil SRV records, got %v", srv)
		}
	})

	t.Run("LookupTXT", func(t *testing.T) {
		t.Parallel()
		txt, err := client.LookupTXT(ctx, "example.com")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if txt != nil {
			t.Errorf("expected nil TXT records, got %v", txt)
		}
	})
}

func TestGonnectClient_InterfaceNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.GonnectClient{Client: &socksgo.Client{}}

	t.Run("Interfaces", func(t *testing.T) {
		t.Parallel()
		ifaces, err := client.Interfaces()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(ifaces) != 0 {
			t.Errorf("expected empty interfaces, got %d", len(ifaces))
		}
	})

	t.Run("InterfaceAddrs", func(t *testing.T) {
		t.Parallel()
		addrs, err := client.InterfaceAddrs()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(addrs) != 0 {
			t.Errorf("expected empty addrs, got %d", len(addrs))
		}
	})

	t.Run("InterfacesByIndex", func(t *testing.T) {
		t.Parallel()
		ifaces, err := client.InterfacesByIndex(1)
		if err == nil {
			t.Error("expected error, got nil")
		}
		if ifaces != nil {
			t.Errorf("expected nil interfaces, got %d", len(ifaces))
		}
	})

	t.Run("InterfacesByName", func(t *testing.T) {
		t.Parallel()
		ifaces, err := client.InterfacesByName("lo")
		if err == nil {
			t.Error("expected error, got nil")
		}
		if ifaces != nil {
			t.Errorf("expected nil interfaces, got %d", len(ifaces))
		}
	})
}

func TestGonnectClient_InterfaceAssertions(t *testing.T) {
	t.Parallel()

	// Verify interface implementations at runtime
	var _ gonnect.Resolver = &socksgo.GonnectClient{}
	var _ gonnect.InterfaceNetwork = &socksgo.GonnectClient{}

	client := &socksgo.GonnectClient{Client: &socksgo.Client{}}

	// Type assertion check
	if _, ok := any(client).(gonnect.Resolver); !ok {
		t.Error("GonnectClient does not implement gonnect.Resolver")
	}
	if _, ok := any(client).(gonnect.InterfaceNetwork); !ok {
		t.Error("GonnectClient does not implement gonnect.InterfaceNetwork")
	}
}

func TestGonnectClient_WrappedClient(t *testing.T) {
	t.Parallel()

	// Test that GonnectClient can wrap a real Client
	wrappedClient := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "localhost:1080",
	}
	gc := &socksgo.GonnectClient{Client: wrappedClient}

	// Verify the wrapped client is accessible
	if gc.Client != wrappedClient {
		t.Error("wrapped client not accessible")
	}
	if gc.Client.SocksVersion != "5" {
		t.Errorf("expected SocksVersion '5', got %q", gc.Client.SocksVersion)
	}
}
