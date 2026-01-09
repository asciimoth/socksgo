package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/asciimoth/socksgo/internal"
)

// Static type assertion
var (
	_ AuthMethod  = &PassAuthMethod{}
	_ AuthHandler = &PassAuthHandler{}
)

type PassAuthMethod struct {
	User, Pass string
}

func (m *PassAuthMethod) Code() AuthMethodCode {
	return PassAuthCode
}

func (m *PassAuthMethod) Name() string {
	return m.Code().String()
}

func (m *PassAuthMethod) RunAuth(conn net.Conn, pool BufferPool) (net.Conn, AuthInfo, error) {
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

	buf := internal.GetBuffer(pool, 3+len(user)+len(pass))
	defer internal.PutBuffer(pool, buf)

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
		return conn, info, fmt.Errorf("unknown user+pass auth version %d", buf[0])
	}

	if buf[1] != 0 {
		return conn, info, fmt.Errorf("user+pass auth rejected by server")
	}

	return conn, info, nil
}

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

func (m *PassAuthHandler) verify(user, pass string) bool {
	if m.VerifyFn == nil {
		return true
	}
	return m.VerifyFn(user, pass)
}

func (m *PassAuthHandler) HandleAuth(conn net.Conn, pool BufferPool) (net.Conn, AuthInfo, error) {
	info := AuthInfo{
		Code: m.Code(),
	}

	buf := internal.GetBuffer(pool, MAX_HEADER_STR_LENGTH+1)
	defer internal.PutBuffer(pool, buf)

	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return conn, info, err
	}

	if buf[0] != 1 {
		return conn, info, fmt.Errorf("unknown user+pass auth version %d", buf[0])
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
