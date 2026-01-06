package protocol_test

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/asciimoth/socks/internal"
)

// Static type assertion.
var (
	_ net.Addr       = NetAddr{}
	_ net.Conn       = &MockConn{}
	_ net.Conn       = &MockPacketConn{}
	_ net.PacketConn = &MockPacketConn{}
)

type NetAddr struct {
	Addr string
	Net  string
}

func (a NetAddr) String() string {
	return a.Addr
}

func (a NetAddr) Network() string {
	return a.Net
}

type MockConn struct {
	bytes.Buffer
	Local, Remote net.Addr
}

func (c *MockConn) Close() error {
	return nil
}

func (c *MockConn) LocalAddr() net.Addr {
	return c.Local
}

func (c *MockConn) RemoteAddr() net.Addr {
	return c.Remote
}

func (c *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type Packet struct {
	Addr    net.Addr
	Payload []byte
}

type MockPacketConn struct {
	Packets       []Packet
	Local, Remote net.Addr
}

func (c *MockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if len(c.Packets) < 1 {
		err = errors.New("no packets left")
		return
	}
	packet := c.Packets[len(c.Packets)-1]
	c.Packets = c.Packets[:len(c.Packets)-1]
	addr = packet.Addr
	n = copy(p, packet.Payload)
	return
}

func (c *MockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	packet := Packet{
		Addr:    addr,
		Payload: internal.CopyBytes(p),
	}
	c.Packets = append(c.Packets, packet)
	return len(p), nil
}

func (c *MockPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *MockPacketConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, nil)
}

func (c *MockPacketConn) Close() error {
	return nil
}

func (c *MockPacketConn) LocalAddr() net.Addr {
	return c.Local
}

func (c *MockPacketConn) RemoteAddr() net.Addr {
	return c.Remote
}

func (c *MockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *MockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *MockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
