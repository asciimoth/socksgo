package protocol

// Protocol helper utilities.
//
// This file provides common helper functions used across SOCKS4 and SOCKS5
// implementations, including reply building and error handling.

import (
	"bytes"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
)

// Reply sends a SOCKS reply packet.
//
// Builds and sends a protocol-specific reply (SOCKS4 or SOCKS5) with
// automatic status code conversion between protocol versions.
//
// # Protocol Versions
//
//   - "4" / "4a": Uses SOCKS4 reply format, status converted via To4()
//   - "5" / "5h": Uses SOCKS5 reply format, status converted via To5()
//
// # Parameters
//
//   - ver: Protocol version ("4", "4a", "5", or "5h")
//   - conn: Connection to send reply on
//   - stat: Reply status code (automatically converted to appropriate format)
//   - addr: Bound address to include in reply
//   - pool: Buffer pool for allocation
//
// # Returns
//
// Error if building or sending the reply fails.
//
// # Examples
//
//	// SOCKS5 success reply
//	addr := protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 8080, "tcp")
//	err := protocol.Reply("5", conn, protocol.SuccReply, addr, pool)
//
//	// SOCKS4 rejection reply
//	err := protocol.Reply("4", conn, protocol.Rejected, addr, pool)
func Reply(
	ver string, // "4" | "4a" | "5" | "5h"
	conn net.Conn,
	stat ReplyStatus,
	addr Addr,
	pool bufpool.Pool,
) (err error) {
	var reply []byte
	switch ver {
	case "5", "5h":
		reply, err = BuildSocks5TCPReply(stat.To5(), addr, pool)
	case "4", "4a":
		reply = BuildSocks4TCPReply(stat.To4(), addr, pool)
	}
	if err != nil {
		return
	}
	defer bufpool.PutBuffer(pool, reply)
	_, err = io.Copy(conn, bytes.NewReader(reply))
	return
}

// Reject sends a rejection reply and closes the connection.
//
// A convenience function that sends a failure reply with a zero
// bound address (0.0.0.0:0) and closes the connection.
//
// # Parameters
//
//   - ver: Protocol version ("4", "4a", "5", or "5h")
//   - conn: Connection to reject
//   - stat: Rejection status code
//   - pool: Buffer pool for allocation
//
// # Behavior
//
// The connection is always closed, even if sending the reply fails.
//
// # Examples
//
//	// Reject SOCKS5 request
//	protocol.Reject("5", conn, protocol.DisallowReply, pool)
//
//	// Reject SOCKS4 request
//	protocol.Reject("4", conn, protocol.Rejected, pool)
func Reject(
	ver string, // "4" | "4a" | "5" | "5h"
	conn net.Conn,
	stat ReplyStatus,
	pool bufpool.Pool,
) {
	defer func() { _ = conn.Close() }()
	addr := AddrFromIP(net.IPv4(0, 0, 0, 0).To4(), 0, "")
	_ = Reply(ver, conn, stat, addr, pool)
}
