package protocol

import (
	"fmt"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
)

// Static type assertion
var (
	_ AuthMethod  = &GSSAuthMethod{}
	_ AuthHandler = &GSSAuthHandler{}
)

// GSSAPIClient is implemented by the client-side GSS library.
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

// GSSAPIServer is implemented by the server-side GSS library.
type GSSAPIServer interface {
	// AcceptSecContext processes a token from the client, returning a token to send back.
	// Returns outputToken, the authenticated principal (srcName), needContinue flag, or err.
	AcceptSecContext(
		token []byte,
	) (outputToken []byte, srcName string, needContinue bool, err error)

	// DeleteSecContext cleans up the context when done.
	DeleteSecContext() error
}

// GSSAuthMethod implements client-side SOCKS GSS authentication.
type GSSAuthMethod struct {
	Client     GSSAPIClient // Provided GSS implementation
	TargetName string       // e.g. "socks@server.example.com"
}

func (m *GSSAuthMethod) Code() AuthMethodCode { return GSSAuthCode }
func (m *GSSAuthMethod) Name() string         { return m.Code().String() }

// TODO: Implement per message protection
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
			if _, err := conn.Write(header); err != nil {
				return conn, info, err
			}
			if _, err := conn.Write(outToken); err != nil {
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

// GSSAuthHandler implements server-side SOCKS GSS authentication.
type GSSAuthHandler struct {
	Server GSSAPIServer // Provided GSS implementation
}

func (h *GSSAuthHandler) Code() AuthMethodCode { return GSSAuthCode }
func (h *GSSAuthHandler) Name() string         { return h.Code().String() }

// TODO: Implement per message protection
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
			return conn, info, fmt.Errorf("invalid GSS frame from client")
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
