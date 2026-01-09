package protocol_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

type MockGSSClient struct {
	Rounds int // number of client<->server exchanges before completion
	step   int // internal state
}

func (m *MockGSSClient) InitSecContext(targetName string, token []byte) ([]byte, bool, error) {
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

type MockGSSServer struct {
	Rounds    int
	Principal string
	step      int
}

func (m *MockGSSServer) AcceptSecContext(token []byte) ([]byte, string, bool, error) {
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

func runGSSAuthTest(
	method protocol.GSSAuthMethod, handler protocol.GSSAuthHandler,
) (
	clientInfo, serverInfo protocol.AuthInfo,
	clientErr, serverErr error,
) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	readyCh := make(chan any, 2)

	// Server side
	go func() {
		_, serverInfo, serverErr = handler.HandleAuth(serverConn, nil)
		readyCh <- nil
	}()

	// Client side
	go func() {
		_, clientInfo, clientErr = method.RunAuth(clientConn, nil)
		readyCh <- nil
	}()

	for range 2 {
		<-readyCh
	}
	return
}

func TestGSSAuth(t *testing.T) {
	for i := range 9 {
		clientGSS := &MockGSSClient{Rounds: i + 1}
		serverGSS := &MockGSSServer{Rounds: i + 1, Principal: "client@mock"}

		_, _, cE, sE := runGSSAuthTest(
			protocol.GSSAuthMethod{Client: clientGSS, TargetName: "socks@server"},
			protocol.GSSAuthHandler{Server: serverGSS},
		)

		if cE != nil {
			t.Errorf("GSS Client failed: %v", cE)
		}

		if sE != nil {
			t.Errorf("GSS Server failed: %v", sE)
		}
	}
}
