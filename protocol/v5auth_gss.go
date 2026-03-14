package protocol

// GSS-API Authentication for SOCKS5.
//
// This file implements a stub for GSS-API authentication as defined in
// RFC 1961: GSS-API Authentication Method for SOCKS Version 5.
//
// # Overview
//
// GSS-API (Generic Security Service Application Program Interface) provides
// secure authentication with support for encryption and integrity protection.
// It's commonly used with Kerberos for enterprise authentication.
//
// # Status
//
// This implementation is a STUB. It provides the framework for GSS-API
// authentication but requires an external GSS-API library (like MIT
// Kerberos or Heimdal) to function.
//
// # Protocol Overview
//
// GSS-API authentication uses a token exchange mechanism:
//
// 1. Client sends method list including GSSAuthCode (0x01)
// 2. Server selects GSS-API authentication
// 3. Multiple token exchanges:
//    - Client -> Server: GSS token (framed with 4-byte header)
//    - Server -> Client: GSS token (framed with 4-byte header)
// 4. When GSS_S_COMPLETE is reached, authentication succeeds
//
// # Token Frame Format
//
//	+----+----+-----+-----+----------+
//	|VER |MTYP| LEN | ... |  TOKEN   |
//	+----+----+-----+-----+----------+
//	| 1  | 1  |  2  |     | Variable |
//	+----+----+-----+-----+----------+
//
// Where:
//   - VER: Version (0x01)
//   - MTYP: Message type (0x01 for authentication)
//   - LEN: Token length (big-endian uint16)
//   - TOKEN: GSS-API token
//
// # Usage
//
// This requires a GSS-API implementation. Example with a hypothetical library:
//
//	// Client-side
//	gssClient := &myGSS.Client{ServiceName: "socks@proxy.example.com"}
//	method := &protocol.GSSAuthMethod{
//	    Client: gssClient,
//	    TargetName: "socks@proxy.example.com",
//	}
//
//	// Server-side
//	gssServer := &myGSS.Server{Keytab: "/etc/krb5.keytab"}
//	handler := &protocol.GSSAuthHandler{Server: gssServer}
//
// # References
//
//   - RFC 1961: GSS-API Authentication Method for SOCKS Version 5
//   - RFC 2743: Generic Security Service API Version 2

import (
	"fmt"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/internal"
)

// Static type assertion
var (
	_ AuthMethod  = &GSSAuthMethod{}
	_ AuthHandler = &GSSAuthHandler{}
)

// GSSAPIClient is the interface for client-side GSS-API implementations.
//
// This interface should be implemented by a GSS-API library wrapper
// (e.g., MIT Kerberos, Heimdal).
//
// # Methods
//
//   - InitSecContext: Initialize security context and produce tokens
//   - DeleteSecContext: Clean up context resources
//
// # Implementation Notes
//
// The implementation should:
// 1. On first call with nil token, initiate GSS context
// 2. Process server tokens and produce response tokens
// 3. Return needContinue=false when GSS_S_COMPLETE is reached
// 4. Handle context cleanup in DeleteSecContext
type GSSAPIClient interface {
	// InitSecContext produces a context token to send to the server.
	// `token` is the input from the peer (nil on first call).
	// Returns outputToken (to send), needContinue=true if more tokens are needed, or err.
	InitSecContext(
		targetName string,
		token []byte,
	) (outputToken []byte, needContinue bool, err error)

	// DeleteSecContext cleans up the context when done.
	DeleteSecContext() error
}

// GSSAPIServer is the interface for server-side GSS-API implementations.
//
// This interface should be implemented by a GSS-API library wrapper
// (e.g., MIT Kerberos, Heimdal) for server-side authentication.
//
// # Methods
//
//   - AcceptSecContext: Process client tokens and produce response tokens
//   - DeleteSecContext: Clean up context resources
//
// # Implementation Notes
//
// The implementation should:
// 1. Process client tokens through AcceptSecContext
// 2. Return the authenticated principal name (srcName) on success
// 3. Return needContinue=false when GSS_S_COMPLETE is reached
// 4. Handle context cleanup in DeleteSecContext
type GSSAPIServer interface {
	// AcceptSecContext processes a token from the client, returning a token to send back.
	// Returns outputToken, the authenticated principal (srcName), needContinue flag, or err.
	AcceptSecContext(
		token []byte,
	) (outputToken []byte, srcName string, needContinue bool, err error)

	// DeleteSecContext cleans up the context when done.
	DeleteSecContext() error
}

// GSSAuthMethod implements client-side GSS-API authentication.
//
// GSSAuthMethod wraps a GSSAPIClient implementation to provide
// SOCKS5 GSS-API authentication. It handles token framing and exchange.
//
// # Fields
//
//   - Client: GSS-API client implementation (required)
//   - TargetName: Service principal name (e.g., "socks@proxy.example.com")
//
// # Status
//
// This is a STUB implementation. It provides the framework but requires
// an external GSS-API library to function.
//
// # Examples
//
//	// Requires a GSS-API implementation
//	gssClient := &myGSS.Client{ServiceName: "socks@proxy.example.com"}
//	method := &protocol.GSSAuthMethod{
//	    Client: gssClient,
//	    TargetName: "socks@proxy.example.com",
//	}
//	methods := (&protocol.AuthMethods{}).Add(method)
type GSSAuthMethod struct {
	Client     GSSAPIClient // Provided GSS implementation
	TargetName string       // e.g. "socks@server.example.com"
}

func (m *GSSAuthMethod) Code() AuthMethodCode { return GSSAuthCode }
func (m *GSSAuthMethod) Name() string         { return m.Code().String() }

func (m *GSSAuthMethod) RunAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, AuthInfo, error) {
	info := AuthInfo{Code: m.Code()}
	defer func() { _ = m.Client.DeleteSecContext() }()

	// Initial call: no input token yet.
	inputToken := []byte(nil)
	for {
		outToken, needContinue, err := m.Client.InitSecContext(
			m.TargetName,
			inputToken,
		)
		if err != nil {
			return conn, info, fmt.Errorf("GSS init failed: %w", err)
		}
		// If GSS produced a token, send it in a framed message.
		if len(outToken) > 0 {
			header := []byte{
				0x01,                       // ver=1
				0x01,                       // mtyp=1 (authentication)
				byte(len(outToken) >> 8),   //nolint mnd
				byte(len(outToken) & 0xff), //nolint mnd
			}
			if _, err := internal.WriteAllSlices(
				conn,
				header,
				outToken,
			); err != nil {
				return conn, info, err
			}
		}
		if !needContinue {
			// Context established (GSS_S_COMPLETE); we're done.
			break
		}
		// Read the next token from server (framed similarly).
		hdr := make([]byte, 4) //nolint mnd
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return conn, info, err
		}
		if hdr[0] != 0x01 || hdr[1] != 0x01 {
			return conn, info, fmt.Errorf(
				"invalid GSS frame: ver=0x%x mtyp=0x%x",
				hdr[0],
				hdr[1],
			)
		}
		tokLen := int(hdr[2])<<8 | int(hdr[3]) //nolint mnd
		inputToken = make([]byte, tokLen)
		if _, err := io.ReadFull(conn, inputToken); err != nil {
			return conn, info, err
		}
		// Loop to feed the token into InitSecContext() again.
	}
	// On success, return AuthInfo with GSS code. Name field left empty (could fill from context if needed).
	// NOTE: Should we provide more info?
	return conn, info, nil
}

// GSSAuthHandler implements server-side GSS-API authentication.
//
// GSSAuthHandler wraps a GSSAPIServer implementation to provide
// SOCKS5 GSS-API authentication. It handles token framing and exchange.
//
// # Fields
//
//   - Server: GSS-API server implementation (required)
//
// # Status
//
// This is a STUB implementation. It provides the framework but requires
// an external GSS-API library to function.
//
// # Examples
//
//	// Requires a GSS-API implementation
//	gssServer := &myGSS.Server{Keytab: "/etc/krb5.keytab"}
//	handler := &protocol.GSSAuthHandler{Server: gssServer}
//	handlers := (&protocol.AuthHandlers{}).Add(handler)
type GSSAuthHandler struct {
	Server GSSAPIServer // Provided GSS implementation
}

func (h *GSSAuthHandler) Code() AuthMethodCode { return GSSAuthCode }
func (h *GSSAuthHandler) Name() string         { return h.Code().String() }

func (h *GSSAuthHandler) HandleAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, AuthInfo, error) {
	info := AuthInfo{Code: h.Code()}
	defer func() { _ = h.Server.DeleteSecContext() }()

	var srcName string
	for {
		// Read header and GSS token from client
		hdr := make([]byte, 4) //nolint mnd
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return conn, info, err
		}
		if hdr[0] != 0x01 || hdr[1] != 0x01 {
			return conn, info, fmt.Errorf(
				"invalid GSS frame: ver=0x%x mtyp=0x%x",
				hdr[0],
				hdr[1],
			)
		}
		tokLen := int(hdr[2])<<8 | int(hdr[3])
		clientToken := make([]byte, tokLen)
		if _, err := io.ReadFull(conn, clientToken); err != nil {
			return conn, info, err
		}
		// Feed it to the GSS server acceptor
		outToken, name, needContinue, err := h.Server.AcceptSecContext(
			clientToken,
		)

		srcName = name
		if err != nil {
			return conn, info, fmt.Errorf("GSS accept failed: %w", err)
		}
		// Send any output token back to client
		if needContinue {
			header := []byte{
				0x01, // ver=1
				0x01, // mtyp=1
				byte(len(outToken) >> 8), byte(len(outToken) & 0xff),
			}
			if _, err := conn.Write(header); err != nil {
				return conn, info, err
			}
			if _, err := conn.Write(outToken); err != nil {
				return conn, info, err
			}
		}
		if !needContinue {
			// Context complete; break out.
			break
		}
		// Otherwise loop for next token.
	}
	// Authentication done. srcName is the GSS principal of the client.
	info.Name = srcName
	// NOTE: Should we provide more info?
	return conn, info, nil
}
