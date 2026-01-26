package protocol_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/protocol"
)

func runPassAuthTest(
	method protocol.PassAuthMethod, handler protocol.PassAuthHandler,
	pool bufpool.Pool,
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
		_, serverInfo, serverErr = handler.HandleAuth(serverConn, pool)
		readyCh <- nil
	}()

	// Client side
	go func() {
		_, clientInfo, clientErr = method.RunAuth(clientConn, pool)
		readyCh <- nil
	}()

	for range 2 {
		<-readyCh
	}
	return
}

func TestPassAuth(t *testing.T) {
	var user, pass string
	defaultVerify := func(u, p string) bool {
		return u == user && p == pass
	}

	tests := []struct {
		name string

		user     string
		pass     string
		verifyFn func(user, pass string) bool

		clientErr, serverErr error
	}{
		{
			name:     "Successful",
			user:     "alice",
			pass:     "secret123",
			verifyFn: defaultVerify,
		},
		{
			name: "AcceptAny",
			user: "alice",
			pass: "secret123",
		},
		{
			name: "Reject",
			user: "alice",
			pass: "secret123",
			verifyFn: func(_, _ string) bool {
				return false
			},
			clientErr: fmt.Errorf("user+pass auth rejected by server"),
			serverErr: fmt.Errorf("provided user+pass rejected"),
		},
		{
			name:     "VoidUser",
			user:     "",
			pass:     "secret123",
			verifyFn: defaultVerify,
		},
		{
			name:     "VoidPass",
			user:     "alice",
			pass:     "",
			verifyFn: defaultVerify,
		},
		{
			name:     "VoidUserPass",
			user:     "",
			pass:     "",
			verifyFn: defaultVerify,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			user = tt.user
			pass = tt.pass

			method := protocol.PassAuthMethod{User: user, Pass: pass}
			handler := protocol.PassAuthHandler{
				VerifyFn: tt.verifyFn,
			}

			clientInfo, serverInfo, clientErr, serverErr := runPassAuthTest(method, handler, pool)

			if fmt.Sprintf("%s", clientErr) != fmt.Sprintf("%s", tt.clientErr) {
				t.Errorf("client err %s while expected %s", clientErr, tt.clientErr)
			}
			if fmt.Sprintf("%s", serverErr) != fmt.Sprintf("%s", tt.serverErr) {
				t.Errorf("server err %s while expected %s", serverErr, tt.serverErr)
			}

			if clientErr == nil {
				if clientInfo.Code != protocol.PassAuthCode {
					t.Errorf("expected client auth code %v, got %v", protocol.PassAuthCode, clientInfo.Code)
				}
				if _, v := protocol.GetAuthParam[string](clientInfo, "user"); v != user {
					t.Errorf("expected client user %v, got %v", user, v)
				}
				if _, v := protocol.GetAuthParam[string](clientInfo, "pass"); v != pass {
					t.Errorf("expected client pass %v, got %v", user, v)
				}
			}
			if serverErr == nil {
				if serverInfo.Code != protocol.PassAuthCode {
					t.Errorf("expected server auth code %v, got %v", protocol.PassAuthCode, serverInfo.Code)
				}
				if _, v := protocol.GetAuthParam[string](serverInfo, "user"); v != user {
					t.Errorf("expected server user %v, got %v", user, v)
				}
				if _, v := protocol.GetAuthParam[string](serverInfo, "pass"); v != pass {
					t.Errorf("expected server pass %v, got %v", user, v)
				}
			}

		})
	}
}
