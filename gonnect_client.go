package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/gonnect"
)

// Static type assertions
var (
	_ gonnect.Network          = &GonnectClient{}
	_ gonnect.Resolver         = &GonnectClient{}
	_ gonnect.InterfaceNetwork = &GonnectClient{}
)

// GonnectClient wraps a Client to implement gonnect.Resolver and
// gonnect.InterfaceNetwork interfaces. Resolver methods return "not found"
// errors as DNS resolution through SOCKS requires TorLookup to be enabled.
// InterfaceNetwork methods return empty results as SOCKS proxies don't
// expose local network interfaces.
type GonnectClient struct {
	*Client
}

// LookupCNAME implements gonnect.Resolver.LookupCNAME.
// Returns a "not found" error as CNAME lookup is not supported.
func (gc *GonnectClient) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return "", &net.DNSError{
		Err:        "not found",
		Name:       host,
		IsNotFound: true,
	}
}

// LookupPort implements gonnect.Resolver.LookupPort.
// Returns a "not found" error as port lookup is not supported.
func (gc *GonnectClient) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	return gonnect.LookupPortOffline(network, service)
}

// LookupNS implements gonnect.Resolver.LookupNS.
// Returns a "not found" error as NS lookup is not supported.
func (gc *GonnectClient) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return nil, &net.DNSError{
		Err:        "not found",
		Name:       name,
		IsNotFound: true,
	}
}

// LookupMX implements gonnect.Resolver.LookupMX.
// Returns a "no such host" error as MX lookup is not supported.
func (gc *GonnectClient) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return nil, &net.DNSError{
		Err:        "no such host",
		Name:       name,
		IsNotFound: true,
	}
}

// LookupSRV implements gonnect.Resolver.LookupSRV.
// Returns a "no such host" error as SRV lookup is not supported.
func (gc *GonnectClient) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return "", nil, &net.DNSError{
		Err:        "no such host",
		Name:       "_svc._" + proto + "." + name,
		IsNotFound: true,
	}
}

// LookupTXT implements gonnect.Resolver.LookupTXT.
// Returns a "no such host" error as TXT lookup is not supported.
func (gc *GonnectClient) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return nil, &net.DNSError{
		Err:        "no such host",
		Name:       name,
		IsNotFound: true,
	}
}

// Interfaces implements gonnect.InterfaceNetwork.Interfaces.
// Returns an empty slice as SOCKS proxies don't expose local interfaces.
func (gc *GonnectClient) Interfaces() ([]gonnect.NetworkInterface, error) {
	return []gonnect.NetworkInterface{}, nil
}

// InterfaceAddrs implements gonnect.InterfaceNetwork.InterfaceAddrs.
// Returns an empty slice as SOCKS proxies don't expose local addresses.
func (gc *GonnectClient) InterfaceAddrs() ([]net.Addr, error) {
	return []net.Addr{}, nil
}

// InterfacesByIndex implements gonnect.InterfaceNetwork.InterfacesByIndex.
// Returns an interface-not-found error as no interfaces are available.
func (gc *GonnectClient) InterfacesByIndex(
	index int,
) ([]gonnect.NetworkInterface, error) {
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}

// InterfacesByName implements gonnect.InterfaceNetwork.InterfacesByName.
// Returns an interface-not-found error as no interfaces are available.
func (gc *GonnectClient) InterfacesByName(
	name string,
) ([]gonnect.NetworkInterface, error) {
	return nil, &net.AddrError{Err: "interface not found", Addr: ""}
}
