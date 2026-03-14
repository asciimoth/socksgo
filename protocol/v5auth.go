package protocol

// SOCKS5 Authentication Framework.
//
// This file implements the SOCKS5 authentication negotiation mechanism
// as defined in RFC 1928 and RFC 1929.
//
// # Authentication Methods
//
// SOCKS5 supports multiple authentication methods:
//   - No Auth (0x00): No authentication required
//   - GSS-API (0x01): GSS-API authentication (RFC 1961)
//   - Username/Password (0x02): Plain text credentials (RFC 1929)
//   - No Acceptable Methods (0xFF): Server rejection
//
// # Negotiation Flow
//
//  1. Client sends method list:
//     +----+----------+----------+------+
//     |VER | NMETHODS | METHODS  | ...  |
//     +----+----------+----------+------+
//     | 1  |    1     | 1 to 255 |      |
//     +----+----------+----------+------+
//
//  2. Server selects method:
//     +----+--------+
//     |VER | METHOD |
//     +----+--------+
//     | 1  |   1    |
//     +----+--------+
//
//  3. If method requires authentication (e.g., Username/Password),
//     the appropriate sub-protocol is executed.
//
// # Architecture
//
// The framework uses two interfaces:
//   - AuthMethod: Client-side authentication implementation
//   - AuthHandler: Server-side authentication implementation
//
// Collections:
//   - AuthMethods: Client-side method list
//   - AuthHandlers: Server-side handler registry
//
// # Files
//
//   - v5auth.go: Core framework and interfaces
//   - v5auth_pass.go: Username/Password authentication (RFC 1929)
//   - v5auth_gss.go: GSS-API authentication

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/asciimoth/bufpool"
)

// Authentication method codes as defined in RFC 1928.
const (
	// NoAuthCode indicates no authentication is required.
	// Wire value: 0x00
	NoAuthCode AuthMethodCode = 0x0

	// GSSAuthCode indicates GSS-API authentication.
	// Wire value: 0x01
	GSSAuthCode AuthMethodCode = 0x1

	// PassAuthCode indicates username/password authentication.
	// Wire value: 0x02
	PassAuthCode AuthMethodCode = 0x02

	// NoAccAuthCode indicates no acceptable authentication methods.
	// Used by server to reject all client-proposed methods.
	// Wire value: 0xFF
	NoAccAuthCode AuthMethodCode = 0xff
)

var (
	DefaultMethodSelectionMsg = []byte{
		5, // VER
		1, // NMETHODS
		byte(NoAuthCode),
	}
)

// AuthMethodCode represents a SOCKS5 authentication method identifier.
//
// AuthMethodCode is used in the authentication negotiation phase to
// advertise supported methods (client) or select a method (server).
//
// # Standard Values
//
//   - 0x00: No authentication required
//   - 0x01: GSS-API
//   - 0x02: Username/Password
//   - 0x03-0x7F: IANA assigned
//   - 0x80-0xFE: Private methods
//   - 0xFF: No acceptable methods
//
// # Examples
//
//	code := protocol.PassAuthCode
//	if code == protocol.PassAuthCode {
//	    // Handle username/password auth
//	}
//
//	// String representation
//	code.String() // Returns "user-pass auth"
type AuthMethodCode uint8

func (a AuthMethodCode) String() string {
	if a >= 0x3 && a <= 0x7f {
		return "IANA assigned auth"
	}
	if a >= 0x80 && a <= 0xfe {
		return "private auth method"
	}
	name := "auth method no" + strconv.Itoa(int(a))
	// Standard auth method
	switch a {
	case NoAuthCode:
		name = "no auth required"
	case GSSAuthCode:
		name = "GSS auth"
	case PassAuthCode:
		name = "user-pass auth"
	case NoAccAuthCode:
		name = "no acceptable auth methods"
	}
	return name
}

// AuthInfo provides information about a successful authentication.
//
// AuthInfo is returned after successful authentication and contains
// details about the method used and any relevant credentials or
// session information.
//
// # Fields
//
//   - Code: The authentication method code used
//   - Name: Human-readable method name (may be empty, use GetName())
//   - Info: Method-specific information (e.g., username for PassAuth)
//
// # Examples
//
//	// After authentication
//	info, err := protocol.RunAuth(conn, pool, methods)
//	if err == nil {
//	    fmt.Printf("Authenticated with: %s\n", info.GetName())
//	    if user, ok := protocol.GetAuthParam[string](info, "user"); ok {
//	        fmt.Printf("User: %s\n", user)
//	    }
//	}
type AuthInfo struct {
	Code AuthMethodCode
	Name string // May be ""; Use GetName()
	Info map[string]any
}

func (a AuthInfo) String() string {
	var str strings.Builder
	fmt.Fprintf(&str, "%d %s\n", a.Code, a.GetName())
	pairs := make([]string, 0, len(a.Info))
	for k, v := range a.Info {
		pairs = append(pairs, fmt.Sprintf("%s: %v", k, v)) //nolint makezero
	}
	sort.Strings(pairs)
	for _, pair := range pairs {
		_, _ = str.WriteString(pair)
	}
	return str.String()
}

func (a AuthInfo) GetName() string {
	if a.Name == "" {
		return a.Code.String()
	}
	return a.Name
}

// GetAuthParam retrieves a typed parameter from AuthInfo.Info.
//
// This is a type-safe helper for extracting authentication parameters.
// Returns (false, zero) if the key doesn't exist or the type doesn't match.
//
// # Type Parameter
//
// # T - The expected type of the parameter
//
// # Examples
//
//	info, _ := protocol.RunAuth(conn, pool, methods)
//
//	if user, ok := protocol.GetAuthParam[string](info, "user"); ok {
//	    fmt.Printf("Username: %s\n", user)
//	}
//
//	if token, ok := protocol.GetAuthParam[[]byte](info, "token"); ok {
//	    // Use GSS token
//	}
func GetAuthParam[T any](info AuthInfo, key string) (ok bool, val T) {
	if info.Info == nil {
		return
	}
	var v any
	v, ok = info.Info[key]
	if ok {
		val, ok = v.(T)
	}
	return
}

// AuthMethod is the client-side authentication interface.
//
// AuthMethod implementations handle the client side of SOCKS5
// authentication protocols. Each method (NoAuth, PassAuth, GSSAuth)
// has its own implementation.
//
// # Implementation Requirements
//
//   - Code() must return a valid method code (not 0x00 or 0xFF)
//   - RunAuth() performs the authentication handshake
//   - Name() returns a human-readable description
//
// # Usage
//
//	methods := (&protocol.AuthMethods{}).Add(&protocol.PassAuthMethod{
//	    User: "username",
//	    Pass: "password",
//	})
//	conn, info, err := protocol.RunAuth(conn, pool, methods)
type AuthMethod interface {
	Name() string

	// AuthMethods with Code() == 0x0 or Code() == 0xff are invalid
	Code() AuthMethodCode

	RunAuth(conn net.Conn, pool bufpool.Pool) (net.Conn, AuthInfo, error)
}

// AuthHandler is the server-side authentication interface.
//
// AuthHandler implementations handle the server side of SOCKS5
// authentication protocols. Each method (NoAuth, PassAuth, GSSAuth)
// has its own handler implementation.
//
// # Implementation Requirements
//
//   - Code() must return a valid method code (not 0x00 or 0xFF)
//   - HandleAuth() performs the authentication handshake
//   - Name() returns a human-readable description
//
// # Usage
//
//	handlers := (&protocol.AuthHandlers{}).Add(&protocol.PassAuthHandler{
//	    Verify: func(user, pass string) bool {
//	        return user == "admin" && pass == "secret"
//	    },
//	})
//	conn, info, err := protocol.HandleAuth(conn, pool, handlers)
type AuthHandler interface {
	Name() string

	// AuthHandlers with Code() == 0x0 or Code() == 0xff are invalid
	Code() AuthMethodCode

	HandleAuth(conn net.Conn, pool bufpool.Pool) (net.Conn, AuthInfo, error)
}

// NoAuthHandler implements server-side no-authentication.
//
// This handler accepts any connection without requiring credentials.
// It's the simplest auth handler and is commonly used for open proxies.
//
// # Wire Format
//
// Server response (2 bytes):
//   - VER: 0x05
//   - METHOD: 0x00 (NoAuth)
//
// # Examples
//
//	handlers := (&protocol.AuthHandlers{}).Add(&protocol.NoAuthHandler{})
type NoAuthHandler struct{}

func (m *NoAuthHandler) Code() AuthMethodCode {
	return NoAuthCode
}

func (m *NoAuthHandler) Name() string {
	return m.Code().String()
}

func (m *NoAuthHandler) HandleAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, AuthInfo, error) {
	info := AuthInfo{
		Code: m.Code(),
	}
	return conn, info, nil
}

// AuthMethods is a client-side collection of authentication methods.
//
// AuthMethods manages a set of authentication methods that the client
// is willing to use. Methods are advertised to the server during
// negotiation, and the selected method is used for authentication.
//
// # Thread Safety
//
// AuthMethods is not thread-safe. Build the method list before
// calling RunAuth.
//
// # Usage
//
//	methods := (&protocol.AuthMethods{}).
//	    Add(&protocol.PassAuthMethod{User: "user", Pass: "pass"}).
//	    Add(&protocol.GSSAuthMethod{Client: gssClient})
//
//	conn, info, err := protocol.RunAuth(conn, pool, methods)
type AuthMethods struct {
	methodsMap map[AuthMethodCode]AuthMethod
	msg        []byte
}

func (m *AuthMethods) Get(code AuthMethodCode) AuthMethod {
	if m == nil || m.methodsMap == nil {
		return nil
	}
	return m.methodsMap[code]
}

func (m *AuthMethods) Add(method AuthMethod) *AuthMethods {
	if m == nil {
		m = &AuthMethods{}
	}
	if method == nil ||
		method.Code() == NoAccAuthCode ||
		method.Code() == NoAuthCode {
		return m
	}
	if m.methodsMap == nil {
		m.methodsMap = map[AuthMethodCode]AuthMethod{
			method.Code(): method,
		}
	} else {
		m.methodsMap[method.Code()] = method
	}
	m.Rebuild()
	return m
}

// If there is PassAuthMethod provided, return its User field.
func (m *AuthMethods) User() string {
	if m == nil || m.methodsMap == nil {
		return ""
	}
	user := ""
	method := m.methodsMap[PassAuthCode]
	if method != nil {
		if p, ok := method.(*PassAuthMethod); ok {
			user = p.User
		}
	}
	return user
}

func (m *AuthMethods) Clone() *AuthMethods {
	var clone *AuthMethods
	for _, v := range m.methodsMap {
		clone = clone.Add(v)
	}
	return clone
}

func (m *AuthMethods) GetMsg() []byte {
	if m == nil || m.msg == nil {
		return DefaultMethodSelectionMsg
	}
	return m.msg
}

func (m *AuthMethods) Rebuild() {
	count := min(len(m.methodsMap), MAX_AUTH_METHODS_COUNT-1)
	if count == 0 {
		// defaultMethodSelectionMsg will be used
		return
	}
	msg := []byte{
		5,               // VER
		byte(count) + 1, // NMETHODS
		byte(NoAuthCode),
	}
	for code := range m.methodsMap {
		if count > 0 {
			msg = append(msg, byte(code))
		}
		count -= 1
	}
	m.msg = msg
}

// AuthHandlers is a server-side collection of authentication handlers.
//
// AuthHandlers manages a set of authentication handlers that the server
// supports. When a client proposes authentication methods, the server
// selects the first matching handler from this collection.
//
// # Default Behavior
//
// For nil or empty AuthHandlers:
//   - Get(NoAuthCode) returns a blank NoAuthHandler
//   - Get(PassAuthCode) returns a PassAuthHandler that accepts any credentials
//
// # Thread Safety
//
// AuthHandlers is not thread-safe. Build the handler list before
// calling HandleAuth.
//
// # Usage
//
//	handlers := (&protocol.AuthHandlers{}).
//	    Add(&protocol.NoAuthHandler{}).
//	    Add(&protocol.PassAuthHandler{
//	        Verify: func(user, pass string) bool {
//	            return isValid(user, pass)
//	        },
//	    })
//
//	conn, info, err := protocol.HandleAuth(conn, pool, handlers)
type AuthHandlers struct {
	handlers map[AuthMethodCode]AuthHandler
}

func (m *AuthHandlers) CheckSocks4User(user string) (accept bool) {
	handler := m.Get(PassAuthCode)
	if handler != nil {
		if pass, ok := handler.(*PassAuthHandler); ok {
			accept = pass.verify(user, "")
		}
	}
	return
}

// For nil or void AuthHandlers
// - Get(NoAuthCode) always return blank method that just do nothing
// - Get(PassAuthCode) always return PassAuthHandler that accept any user+pass
func (m *AuthHandlers) Get(code AuthMethodCode) AuthHandler {
	if m == nil || m.handlers == nil {
		if code == NoAuthCode {
			return &NoAuthHandler{}
		}
		if code == PassAuthCode {
			return &PassAuthHandler{}
		}
		return nil
	}
	return m.handlers[code]
}

func (m *AuthHandlers) Add(handler AuthHandler) *AuthHandlers {
	if m == nil {
		m = &AuthHandlers{}
	}
	if handler == nil ||
		handler.Code() == NoAccAuthCode ||
		handler.Code() == NoAuthCode {
		return m
	}
	if m.handlers == nil {
		m.handlers = map[AuthMethodCode]AuthHandler{
			handler.Code(): handler,
		}
	} else {
		m.handlers[handler.Code()] = handler
	}
	return m
}

// RunAuth performs client-side SOCKS5 authentication negotiation.
//
// Sends the client's method list to the server, reads the server's
// selection, and executes the selected authentication method.
//
// # Negotiation Flow
//
// 1. Send method list: [VER, NMETHODS, METHODS...]
// 2. Read server response: [VER, METHOD]
// 3. If METHOD requires authentication, execute RunAuth() on selected method
//
// # Parameters
//
//   - conn: Network connection to SOCKS5 server
//   - pool: Buffer pool for allocations
//   - methods: Client's authentication methods
//
// # Returns
//
//   - c: Connection (possibly wrapped by auth method)
//   - i: AuthInfo with authentication details
//   - err: Error if negotiation or authentication fails
//
// # Errors
//
//   - ErrNoAcceptableAuthMethods: Server rejected all methods
//   - UnsupportedAuthMethodError: Server selected unsupported method
//   - UnknownAuthVerError: Invalid response version
func RunAuth(
	conn net.Conn, pool bufpool.Pool, methods *AuthMethods,
) (c net.Conn, i AuthInfo, err error) {
	c = conn

	_, err = io.Copy(conn, bytes.NewReader(methods.GetMsg()))
	if err != nil {
		return
	}

	var resp [2]byte
	_, err = io.ReadFull(conn, resp[:])
	if err != nil {
		return
	}

	if resp[0] != 5 { //nolint mnd
		err = UnknownAuthVerError{int(resp[0])} //nolint
		return
	}

	code := AuthMethodCode(resp[1]) //nolint
	i = AuthInfo{
		Code: code,
	}
	if code == NoAuthCode {
		return
	}
	if code == NoAccAuthCode {
		err = ErrNoAcceptableAuthMethods
		return
	}

	method := methods.Get(code)
	if method == nil {
		err = UnsupportedAuthMethodError{code}
		return
	}

	c, i, err = method.RunAuth(conn, pool)
	return
}

// HandleAuth performs server-side SOCKS5 authentication negotiation.
//
// Reads the client's method list, selects a supported method, and
// executes the authentication handshake.
//
// # Negotiation Flow
//
// 1. Read client methods: [VER, NMETHODS, METHODS...]
// 2. Select first matching handler
// 3. Send response: [VER, METHOD]
// 4. If METHOD requires authentication, execute HandleAuth() on selected handler
//
// # Parameters
//
//   - conn: Network connection from SOCKS5 client
//   - pool: Buffer pool for allocations
//   - handlers: Server's authentication handlers
//
// # Returns
//
//   - c: Connection (possibly wrapped by auth handler)
//   - i: AuthInfo with authentication details
//   - err: Error if negotiation or authentication fails
//
// # Errors
//
//   - ErrNoAcceptableAuthMethods: No matching handlers found
//   - Method-specific errors from HandleAuth implementations
func HandleAuth(
	conn net.Conn, pool bufpool.Pool, handlers *AuthHandlers,
) (c net.Conn, i AuthInfo, err error) {
	c = conn

	buf := bufpool.GetBuffer(pool, MAX_AUTH_METHODS_COUNT+1)
	defer bufpool.PutBuffer(pool, buf)

	_, err = io.ReadFull(conn, buf[:1])
	if err != nil {
		return
	}

	count := int(buf[0])
	_, err = io.ReadFull(conn, buf[:count])
	if err != nil {
		return
	}

	var handler AuthHandler
	for _, code := range buf[:count] {
		handler = handlers.Get(AuthMethodCode(code))
		if handler != nil {
			break
		}
	}

	if handler == nil {
		// No acceptable methods
		buf[0] = 5 // Ver
		buf[1] = byte(NoAccAuthCode)
		_, err = io.Copy(conn, bytes.NewReader(buf[:2]))
		if err == nil {
			err = ErrNoAcceptableAuthMethods
		}
		return
	}

	buf[0] = 5 // Ver
	buf[1] = byte(handler.Code())
	_, err = io.Copy(conn, bytes.NewReader(buf[:2]))
	if err == nil {
		c, i, err = handler.HandleAuth(conn, pool)
	}
	return
}
