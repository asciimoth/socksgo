package protocol

// Username/Password Authentication for SOCKS5.
//
// This file implements RFC 1929: Username/Password Authentication for SOCKS V5.
//
// # Protocol Overview
//
// After the server selects username/password authentication (method 0x02),
// the client sends credentials in the following format:
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
//
// Where:
//   - VER: Protocol version (0x01)
//   - ULEN: Username length (1-255)
//   - UNAME: Username (variable length)
//   - PLEN: Password length (1-255)
//   - PASSWD: Password (variable length)
//
// Server response:
//
//	+----+--------+
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
//
// Where STATUS:
//   - 0x00: Success
//   - 0x01: Failure (invalid credentials)
//
// # Security Considerations
//
// Username and password are sent in PLAIN TEXT.
//
// # Usage
//
// Client-side:
//
//	method := &protocol.PassAuthMethod{User: "admin", Pass: "secret"}
//	methods := (&protocol.AuthMethods{}).Add(method)
//	conn, info, err := protocol.RunAuth(conn, pool, methods)
//
// Server-side:
//
//	handler := &protocol.PassAuthHandler{
//	    Verify: func(user, pass string) bool {
//	        return user == "admin" && pass == "secret"
//	    },
//	}
//	handlers := (&protocol.AuthHandlers{}).Add(handler)
//	conn, info, err := protocol.HandleAuth(conn, pool, handlers)

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
)

// Static type assertion
var (
	_ AuthMethod  = &PassAuthMethod{}
	_ AuthHandler = &PassAuthHandler{}
)

// PassAuthMethod implements client-side username/password authentication.
//
// PassAuthMethod sends credentials to the server using the RFC 1929
// protocol. The username and password are sent in plain text.
//
// # Fields
//
//   - User: Username (1-255 bytes)
//   - Pass: Password (1-255 bytes)
//
// # Wire Format
//
// Client request:
//   - VER (1 byte): 0x01
//   - ULEN (1 byte): Username length
//   - UNAME (variable): Username
//   - PLEN (1 byte): Password length
//   - PASSWD (variable): Password
//
// Server response:
//   - VER (1 byte): 0x01
//   - STATUS (1 byte): 0x00=success, 0x01=failure
//
// # Examples
//
//	method := &protocol.PassAuthMethod{
//	    User: "admin",
//	    Pass: "secret",
//	}
//	methods := (&protocol.AuthMethods{}).Add(method)
//	conn, info, err := protocol.RunAuth(conn, pool, methods)
type PassAuthMethod struct {
	User, Pass string
}

func (m *PassAuthMethod) Code() AuthMethodCode {
	return PassAuthCode
}

func (m *PassAuthMethod) Name() string {
	return m.Code().String()
}

func (m *PassAuthMethod) RunAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, AuthInfo, error) {
	info := AuthInfo{
		Code: m.Code(),
		Info: map[string]any{
			"user": m.User,
			"pass": m.Pass,
		},
	}

	user := []byte(m.User)
	pass := []byte(m.Pass)
	if len(user) > MAX_HEADER_STR_LENGTH {
		return conn, info, fmt.Errorf("too long username: %d bytes", len(user))
	}
	if len(pass) > MAX_HEADER_STR_LENGTH {
		return conn, info, fmt.Errorf("too long password: %d bytes", len(pass))
	}

	buf := bufpool.GetBuffer(pool, 3+len(user)+len(pass))
	defer bufpool.PutBuffer(pool, buf)

	pack := buf[:0]
	pack = append(pack, 1)
	pack = append(pack, byte(len(user)))
	pack = append(pack, user...)
	pack = append(pack, byte(len(pass)))
	pack = append(pack, pass...)

	_, err := io.Copy(conn, bytes.NewReader(pack))
	if err != nil {
		return conn, info, err
	}

	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		return conn, info, err
	}

	if buf[0] != 1 {
		return conn, info, fmt.Errorf(
			"unknown user+pass auth version %d",
			buf[0],
		)
	}

	if buf[1] != 0 {
		return conn, info, fmt.Errorf("user+pass auth rejected by server")
	}

	return conn, info, nil
}

// PassAuthHandler implements server-side username/password authentication.
//
// PassAuthHandler validates client credentials using the provided VerifyFn
// function. If VerifyFn is nil, all credentials are accepted (useful for
// testing or open proxies).
//
// # Fields
//
//   - VerifyFn: Validation function. Returns true for valid credentials.
//     If nil, all credentials are accepted.
//
// # Wire Format
//
// See PassAuthMethod for the complete protocol description.
//
// # Examples
//
//	// Strict validation
//	handler := &protocol.PassAuthHandler{
//	    Verify: func(user, pass string) bool {
//	        return user == "admin" && pass == "secret"
//	    },
//	}
//
//	// Accept all credentials
//	handler := &protocol.PassAuthHandler{}
//
//	handlers := (&protocol.AuthHandlers{}).Add(handler)
//	conn, info, err := protocol.HandleAuth(conn, pool, handlers)
type PassAuthHandler struct {
	// Nil means any user+pass combination is allowed
	VerifyFn func(user, pass string) bool
}

func (m *PassAuthHandler) Code() AuthMethodCode {
	return PassAuthCode
}

func (m *PassAuthHandler) Name() string {
	return m.Code().String()
}

func (m *PassAuthHandler) HandleAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, AuthInfo, error) {
	info := AuthInfo{
		Code: m.Code(),
	}

	buf := bufpool.GetBuffer(pool, MAX_HEADER_STR_LENGTH+1)
	defer bufpool.PutBuffer(pool, buf)

	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return conn, info, err
	}

	if buf[0] != 1 {
		return conn, info, fmt.Errorf(
			"unknown user+pass auth version %d",
			buf[0],
		)
	}

	ulen := int(buf[1])
	_, err = io.ReadFull(conn, buf[:ulen+1])
	if err != nil {
		return conn, info, err
	}
	user := string(buf[:ulen])

	plen := int(buf[ulen])
	_, err = io.ReadFull(conn, buf[:plen])
	if err != nil {
		return conn, info, err
	}
	pass := string(buf[:plen])

	info.Info = map[string]any{
		"user": user,
		"pass": pass,
	}

	if m.verify(user, pass) {
		buf[0] = 1 // Ver
		buf[1] = 0 // Succ
		_, err = io.Copy(conn, bytes.NewReader(buf[:2]))
		return conn, info, err
	}

	buf[0] = 1 // Ver
	buf[1] = 1 // Fail
	_, err = io.Copy(conn, bytes.NewReader(buf[:2]))
	_ = conn.Close()

	if err == nil {
		err = fmt.Errorf("provided user+pass rejected")
	}
	return conn, info, err
}

func (m *PassAuthHandler) verify(user, pass string) bool {
	if m.VerifyFn == nil {
		return true
	}
	return m.VerifyFn(user, pass)
}
