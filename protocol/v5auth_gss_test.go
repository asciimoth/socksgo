package protocol_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/protocol"
)

type MockGSSClient struct {
	Rounds int // number of client<->server exchanges before completion
	step   int // internal state
}

func (m *MockGSSClient) InitSecContext(
	targetName string,
	token []byte,
) ([]byte, bool, error) {
	if m.Rounds <= 0 {
		// immediate completion (no tokens)
		return nil, false, nil
	}
	// initial call: token == nil -> produce first client token
	if token == nil {
		m.step = 1
		out := fmt.Appendf(nil, "c:%d", m.step)
		need := m.step < m.Rounds
		return out, need, nil
	}
	// token should be server reply like "s:N"
	// advance and produce next client token if still needed
	m.step++
	if m.step > m.Rounds {
		// already complete
		return nil, false, nil
	}
	out := fmt.Appendf(nil, "c:%d", m.step)
	need := m.step < m.Rounds
	return out, need, nil
}

func (m *MockGSSClient) DeleteSecContext() error { m.step = 0; return nil }

type ErrGSSClient struct{}

func (m *ErrGSSClient) InitSecContext(
	_ string,
	_ []byte,
) ([]byte, bool, error) {
	return nil, false, errors.New("TEST ERROR")
}

func (m *ErrGSSClient) DeleteSecContext() error {
	return errors.New("TEST ERROR")
}

type MockGSSServer struct {
	Rounds    int
	Principal string
	step      int
}

func (m *MockGSSServer) AcceptSecContext(
	token []byte,
) ([]byte, string, bool, error) {
	// token should be "c:N"
	// On first call, token corresponds to c:1, etc.
	m.step++
	if m.step > m.Rounds {
		// protocol error
		return nil, "", false, fmt.Errorf("unexpected extra token")
	}
	// reply with s:STEP
	out := fmt.Appendf(nil, "s:%d", m.step)
	need := m.step < m.Rounds
	src := ""
	if !need {
		src = m.Principal
	}
	return out, src, need, nil
}

func (m *MockGSSServer) DeleteSecContext() error { m.step = 0; return nil }

type ErrGSSServer struct{}

func (m *ErrGSSServer) AcceptSecContext(
	_ []byte,
) ([]byte, string, bool, error) {
	return nil, "", false, errors.New("TEST ERROR")
}

func (m *ErrGSSServer) DeleteSecContext() error {
	return errors.New("TEST ERROR")
}

func runGSSAuthTest(
	method protocol.GSSAuthMethod, handler protocol.GSSAuthHandler,
	pool bufpool.Pool,
) (
	clientInfo, serverInfo protocol.AuthInfo, //nolint
	clientErr, serverErr error,
) {
	clientConn, serverConn := net.Pipe()
	defer func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}()

	readyCh := make(chan any, 2)

	// Server side
	go func() {
		_, serverInfo, serverErr = handler.HandleAuth(serverConn, pool)
		if serverErr != nil {
			_ = serverConn.Close()
		}
		readyCh <- nil
	}()

	// Client side
	go func() {
		_, clientInfo, clientErr = method.RunAuth(clientConn, pool)
		if clientErr != nil {
			_ = clientConn.Close()
		}
		readyCh <- nil
	}()

	for range 2 {
		<-readyCh
	}
	return
}

func TestGSSErrClient(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	clientGSS := &ErrGSSClient{}
	serverGSS := &MockGSSServer{Rounds: 10, Principal: "client@mock"}

	_, _, cE, sE := runGSSAuthTest(
		protocol.GSSAuthMethod{
			Client:     clientGSS,
			TargetName: "socks@server",
		},
		protocol.GSSAuthHandler{Server: serverGSS},
		nil,
	)

	if cE.Error() != "GSS init failed: TEST ERROR" {
		t.Error(cE)
	}

	if sE.Error() != "EOF" {
		t.Error(sE)
	}
}

func TestGSSErrServer(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	clientGSS := &MockGSSClient{Rounds: 10}
	serverGSS := &ErrGSSServer{}

	_, _, cE, sE := runGSSAuthTest(
		protocol.GSSAuthMethod{
			Client:     clientGSS,
			TargetName: "socks@server",
		},
		protocol.GSSAuthHandler{Server: serverGSS},
		nil,
	)

	if cE.Error() != "EOF" {
		t.Error(cE)
	}

	if sE.Error() != "GSS accept failed: TEST ERROR" {
		t.Error(sE)
	}
}

func TestGSSErrBoth(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	clientGSS := &ErrGSSClient{}
	serverGSS := &ErrGSSServer{}

	_, _, cE, sE := runGSSAuthTest(
		protocol.GSSAuthMethod{
			Client:     clientGSS,
			TargetName: "socks@server",
		},
		protocol.GSSAuthHandler{Server: serverGSS},
		nil,
	)

	if cE.Error() != "GSS init failed: TEST ERROR" {
		t.Error(cE)
	}

	if sE.Error() != "EOF" {
		t.Error(sE)
	}
}

func TestGSSAuth(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	for i := range 9 {
		clientGSS := &MockGSSClient{Rounds: i + 1}
		serverGSS := &MockGSSServer{Rounds: i + 1, Principal: "client@mock"}

		_, _, cE, sE := runGSSAuthTest(
			protocol.GSSAuthMethod{
				Client:     clientGSS,
				TargetName: "socks@server",
			},
			protocol.GSSAuthHandler{Server: serverGSS},
			pool,
		)

		if cE != nil {
			t.Errorf("GSS Client failed: %v", cE)
		}

		if sE != nil {
			t.Errorf("GSS Server failed: %v", sE)
		}
	}
}

func TestGSSClientClosedConn(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	_ = a.Close()
	_ = b.Close()
	clientGSS := &MockGSSClient{Rounds: 42}
	method := protocol.GSSAuthMethod{
		Client:     clientGSS,
		TargetName: "socks@server",
	}
	_, _, err := method.RunAuth(a, pool)
	if err.Error() != "io: read/write on closed pipe" {
		t.Error(err)
	}
}

func TestGSSClientInvalidFrame(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		defer func() { _ = b.Close() }()
		for {
			_, err := b.Write([]byte{42, 42, 42, 42})
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { _ = b.Close() }()
		for {
			_, err := b.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	clientGSS := &MockGSSClient{Rounds: 42}
	method := protocol.GSSAuthMethod{
		Client:     clientGSS,
		TargetName: "socks@server",
	}
	_, _, err := method.RunAuth(a, pool)
	if err.Error() != "invalid GSS frame: ver=0x2a mtyp=0x2a" {
		t.Error(err)
	}
}

func TestGSSClientBrokenToken(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		defer func() { _ = b.Close() }()
		_, _ = io.Copy(b, bytes.NewReader([]byte{1, 1, 10 >> 8, 10 & 0xff}))
	}()
	go func() {
		defer func() { _ = b.Close() }()
		for {
			_, err := b.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	clientGSS := &MockGSSClient{Rounds: 42}
	method := protocol.GSSAuthMethod{
		Client:     clientGSS,
		TargetName: "socks@server",
	}
	_, _, err := method.RunAuth(a, pool)
	if err.Error() != "EOF" {
		t.Error(err)
	}
}

func TestGSSAuthNaming(t *testing.T) {
	method := (&protocol.GSSAuthMethod{}).Name()
	handler := (&protocol.GSSAuthHandler{}).Name()

	if method != "GSS auth" || handler != "GSS auth" {
		t.Fatal(method, handler)
	}
}

func TestGSSHandlerInvalidFrame(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		defer func() { _ = b.Close() }()
		for {
			_, err := b.Write([]byte{42, 42, 42, 42})
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { _ = b.Close() }()
		for {
			_, err := b.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	handler := protocol.GSSAuthHandler{&MockGSSServer{Rounds: 42}}
	_, _, err := handler.HandleAuth(a, pool)
	if err.Error() != "invalid GSS frame: ver=0x2a mtyp=0x2a" {
		t.Error(err)
	}
}

func TestGSSHanslerBrokenToken(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		defer func() { _ = b.Close() }()
		_, _ = io.Copy(b, bytes.NewReader([]byte{1, 1, 10 >> 8, 10 & 0xff}))
	}()
	go func() {
		defer func() { _ = b.Close() }()
		for {
			_, err := b.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	handler := protocol.GSSAuthHandler{&MockGSSServer{Rounds: 42}}
	_, _, err := handler.HandleAuth(a, pool)
	if err.Error() != "EOF" {
		t.Error(err)
	}
}

func TestGSSHandlerHeaderWriteFail(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		defer func() { _ = b.Close() }()
		_, _ = io.Copy(b, bytes.NewReader([]byte{1, 1, 1 >> 8, 1 & 0xff, 42}))
	}()
	go func() {
		defer func() { _ = b.Close() }()
		_, _ = b.Read([]byte{0})
	}()
	handler := protocol.GSSAuthHandler{&MockGSSServer{Rounds: 42}}
	_, _, err := handler.HandleAuth(a, pool)
	if err.Error() != "io: read/write on closed pipe" {
		t.Error(err)
	}
}

func TestGSSHandlerTookenWriteFail(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		defer func() { _ = b.Close() }()
		_, _ = io.Copy(b, bytes.NewReader([]byte{1, 1, 1 >> 8, 1 & 0xff, 42}))
	}()
	go func() {
		defer func() { _ = b.Close() }()
		for range 4 {
			_, err := b.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	handler := protocol.GSSAuthHandler{&MockGSSServer{Rounds: 42}}
	_, _, err := handler.HandleAuth(a, pool)
	if err.Error() != "io: read/write on closed pipe" {
		t.Error(err)
	}
}
