package protocol

import (
	"bytes"
	"io"
	"net"

	"github.com/asciimoth/socksgo/internal"
)

// Send socks4/socks5 reply
// Status will be automaticlaly translated to relevant socks version.
func Reply(
	ver string, // "4" | "4a" | "5" | "5h"
	conn net.Conn,
	stat ReplyStatus,
	addr Addr,
	pool BufferPool,
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
	defer internal.PutBuffer(pool, reply)
	_, err = io.Copy(conn, bytes.NewReader(reply))
	return
}

// Send rejection reply & close conn
func Reject(
	ver string, // "4" | "4a" | "5" | "5h"
	conn net.Conn,
	stat ReplyStatus,
	pool BufferPool,
) {
	defer conn.Close()
	addr := AddrFromIP(net.IPv4(0, 0, 0, 0).To4(), 0, "")
	_ = Reply(ver, conn, stat, addr, pool)
}
