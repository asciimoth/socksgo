package socksgo_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo"
)

func TestUDPAssocListenPacketEcho(t *testing.T) {
	t.Parallel()

	client, cleanup := newUDPListenPacketSocksClientServer(t, "")
	defer cleanup()

	assertUDPEchoThroughNetwork(t, client)
}

func TestGostUDPTunListenPacketEcho(t *testing.T) {
	t.Parallel()

	client, cleanup := newUDPListenPacketSocksClientServer(t, "?gost")
	defer cleanup()

	assertUDPEchoThroughNetwork(t, client)
}

func newUDPListenPacketSocksClientServer(
	t *testing.T,
	query string,
) (*socksgo.Client, func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	network := gonnect.DefaultNetwork(nil)
	server := &socksgo.Server{
		Dialer:         network.Dial,
		PacketDialer:   network.PacketDial,
		Listener:       network.Listen,
		PacketListener: network.ListenPacket,
	}

	ln, err := network.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen SOCKS server: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- server.Accept(ctx, conn, false)
	}()

	client, err := socksgo.ClientFromURL(
		"socks5://" + ln.Addr().String() + query,
	)
	if err != nil {
		cancel()
		_ = ln.Close()
		t.Fatalf("create SOCKS client: %v", err)
	}
	client.WithNetwork(gonnect.DetachNetwork(network, nil))
	client.Filter = gonnect.FalseFilter

	cleanup := func() {
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	return client, cleanup
}

func assertUDPEchoThroughNetwork(t *testing.T, network gonnect.Network) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	echo, err := gonnect.DefaultNetwork(nil).ListenPacket(
		ctx,
		"udp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("listen UDP echo server: %v", err)
	}
	defer func() { _ = echo.Close() }()

	echoAddr, err := net.ResolveUDPAddr("udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatalf("resolve UDP echo address: %v", err)
	}

	echoDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		n, addr, err := echo.ReadFrom(buf)
		if err != nil {
			echoDone <- err
			return
		}
		_, err = echo.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		echoDone <- err
	}()

	conn, err := network.ListenPacket(ctx, "udp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("ListenPacket through SOCKS client: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.WriteTo([]byte("ping"), echoAddr); err != nil {
		t.Fatalf("WriteTo through SOCKS client: %v", err)
	}

	if err := conn.SetReadDeadline(
		time.Now().Add(3 * time.Second),
	); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 128)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom through SOCKS client: %v", err)
	}
	if got := string(buf[:n]); got != "echo:ping" {
		t.Fatalf("UDP echo response = %q, want %q", got, "echo:ping")
	}
	if err := <-echoDone; err != nil {
		t.Fatalf("echo server error: %v", err)
	}
}
