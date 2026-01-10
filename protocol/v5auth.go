package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/asciimoth/socksgo/internal"
)

const (
	NoAuthCode    AuthMethodCode = 0x0
	GSSAuthCode   AuthMethodCode = 0x1
	PassAuthCode  AuthMethodCode = 0x02
	NoAccAuthCode AuthMethodCode = 0xff
)

var (
	defaultMethodSelectionMsg = []byte{
		5, // VER
		1, // NMETHODS
		byte(NoAuthCode),
	}
)

type AuthMethodCode uint8

func (a AuthMethodCode) String() string {
	if a >= 0x3 && a <= 0x7f {
		return "IANA assigned auth"
	}
	if a >= 0x80 && a <= 0xfe {
		return "private auth method"
	}
	// Standard auth method
	switch a {
	case NoAuthCode:
		return "no auth required"
	case GSSAuthCode:
		return "GSS auth"
	case PassAuthCode:
		return "user-pass auth"
	case NoAccAuthCode:
		return "no acceptable auth methods"
	default:
		return "auth method no" + strconv.Itoa(int(a))
	}
}

// AuthInfo provides information about successful auth like used password.
type AuthInfo struct {
	Code AuthMethodCode
	Name string // May be ""; Use GetName()
	Info map[string]any
}

func (a AuthInfo) String() string {
	var str strings.Builder
	fmt.Fprintf(&str, "%d %s\n", a.Code, a.GetName())
	for k, v := range a.Info {
		fmt.Fprintf(&str, "%s: %v", k, v)
	}
	return str.String()
}

func (a AuthInfo) GetName() string {
	if a.Name == "" {
		return a.Code.String()
	}
	return a.Name
}

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

// Client side
type AuthMethod interface {
	Name() string

	// AuthMethods with Code() == 0x0 or Code() == 0xff are invalid
	Code() AuthMethodCode

	RunAuth(conn net.Conn, pool BufferPool) (net.Conn, AuthInfo, error)
}

// Server side
type AuthHandler interface {
	Name() string

	// AuthHandlers with Code() == 0x0 or Code() == 0xff are invalid
	Code() AuthMethodCode

	HandleAuth(conn net.Conn, pool BufferPool) (net.Conn, AuthInfo, error)
}

type noAuthHandler struct{}

func (m *noAuthHandler) Code() AuthMethodCode {
	return NoAuthCode
}

func (m *noAuthHandler) Name() string {
	return m.Code().String()
}

func (m *noAuthHandler) HandleAuth(conn net.Conn, pool BufferPool) (net.Conn, AuthInfo, error) {
	info := AuthInfo{
		Code: m.Code(),
	}
	return conn, info, nil
}

type AuthMethods struct {
	methodsMap map[AuthMethodCode]AuthMethod
	msg        []byte
}

func (m *AuthMethods) getMsg() []byte {
	if m == nil || m.msg == nil {
		return defaultMethodSelectionMsg
	}
	return m.msg
}

func (m *AuthMethods) rebuild() {
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
		if count <= 0 {
			break
		}
		count -= 1
		msg = append(msg, byte(code))
	}
	m.msg = msg
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
	m.rebuild()
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
		clone.Add(v)
	}
	return clone
}

type AuthHandlers struct {
	handlers map[AuthMethodCode]AuthHandler
}

func (m *AuthHandlers) CheckSocks4User(user string) bool {
	handler := m.Get(PassAuthCode)
	if handler == nil {
		return false
	}
	pass, ok := handler.(*PassAuthHandler)
	if !ok {
		return false
	}
	return pass.verify(user, "")
}

// For nil or void AuthHandlers
// - Get(NoAuthCode) always return blank method that just do nothing
// - Get(PassAuthCode) always return PassAuthHandler that accept any user+pass
func (m *AuthHandlers) Get(code AuthMethodCode) AuthHandler {
	if m == nil || m.handlers == nil {
		if code == NoAuthCode {
			return &noAuthHandler{}
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

func RunAuth(
	conn net.Conn, pool BufferPool, methods *AuthMethods,
) (c net.Conn, i AuthInfo, err error) {
	c = conn

	_, err = io.Copy(conn, bytes.NewReader(methods.getMsg()))
	if err != nil {
		return
	}

	var resp [2]byte
	_, err = io.ReadFull(conn, resp[:])
	if err != nil {
		return
	}

	if resp[0] != 5 {
		err = fmt.Errorf("unknown auth version %d", resp[0])
		return
	}

	code := AuthMethodCode(resp[1])
	i = AuthInfo{
		Code: code,
	}
	if code == NoAuthCode {
		return
	}
	if code == NoAccAuthCode {
		// TODO: Move to sentinel err var
		err = fmt.Errorf("no acceptable methods")
		return
	}

	method := methods.Get(code)
	if method == nil {
		err = fmt.Errorf("server select unsupported auth method %d", code)
		return
	}

	c, i, err = method.RunAuth(conn, pool)
	return
}

func HandleAuth(
	conn net.Conn, pool BufferPool, handlers *AuthHandlers,
) (c net.Conn, i AuthInfo, err error) {
	c = conn

	buf := internal.GetBuffer(pool, MAX_AUTH_METHODS_COUNT+1)
	defer internal.PutBuffer(pool, buf)

	_, err = io.ReadFull(conn, buf[:1])
	if err != nil {
		return
	}

	// if buf[0] != 5 {
	// 	err = fmt.Errorf("unknown auth version %d", buf[0])
	// 	return
	// }

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
			// TODO: Move to sentinel err var
			err = fmt.Errorf("no acceptable methods")
		}
		return
	}

	buf[0] = 5 // Ver
	buf[1] = byte(handler.Code())
	_, err = io.Copy(conn, bytes.NewReader(buf[:2]))
	if err != nil {
		return
	}

	c, i, err = handler.HandleAuth(conn, pool)
	return
}
