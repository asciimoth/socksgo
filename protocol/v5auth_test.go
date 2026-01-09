package protocol_test

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

func runAuthHandshakeTest(
	methods *protocol.AuthMethods, handlers *protocol.AuthHandlers,
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
		_, serverInfo, serverErr = protocol.HandleAuth(serverConn, nil, handlers)
		readyCh <- nil
	}()

	// Client side
	go func() {
		_, clientInfo, clientErr = protocol.RunAuth(clientConn, nil, methods)
		readyCh <- nil
	}()

	for range 2 {
		<-readyCh
	}
	return
}

func TestAuthHandshake(t *testing.T) {
	tests := []struct {
		name string

		methods  []protocol.AuthMethod
		handlers []protocol.AuthHandler

		code                 protocol.AuthMethodCode
		clientErr, serverErr error
	}{
		{
			name: "NoMethods",
			code: protocol.NoAuthCode,
		},
		{
			name: "PassMethod",
			code: protocol.PassAuthCode,
			methods: []protocol.AuthMethod{
				&protocol.PassAuthMethod{
					User: "alice",
					Pass: "password123",
				},
			},
			handlers: []protocol.AuthHandler{
				&protocol.PassAuthHandler{
					VerifyFn: func(user, pass string) bool {
						return user == "alice" && pass == "password123"
					},
				},
			},
		},
		{
			name: "PassMethodClient",
			code: protocol.NoAuthCode,
			methods: []protocol.AuthMethod{
				&protocol.PassAuthMethod{
					User: "alice",
					Pass: "password123",
				},
			},
		},
		{
			name: "Rejectr",
			code: protocol.NoAuthCode,
			handlers: []protocol.AuthHandler{
				&protocol.PassAuthHandler{
					VerifyFn: func(user, pass string) bool {
						return user == "alice" && pass == "password123"
					},
				},
			},
			clientErr: errors.New("no acceptable methods"),
			serverErr: errors.New("no acceptable methods"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				methods  *protocol.AuthMethods
				handlers *protocol.AuthHandlers
			)
			for _, method := range tt.methods {
				methods = methods.Add(method)
			}
			for _, handler := range tt.handlers {
				handlers = handlers.Add(handler)
			}

			clientInfo, serverInfo, clientErr, serverErr := runAuthHandshakeTest(methods, handlers)

			if fmt.Sprintf("%s", clientErr) != fmt.Sprintf("%s", tt.clientErr) {
				t.Errorf("client err %s while expected %s", clientErr, tt.clientErr)
			}
			if fmt.Sprintf("%s", serverErr) != fmt.Sprintf("%s", tt.serverErr) {
				t.Errorf("server err %s while expected %s", serverErr, tt.serverErr)
			}

			if clientErr == nil && clientInfo.Code != tt.code {
				t.Errorf("expected client auth code %v, got %v", tt.code, clientInfo.Code)
			}
			if serverErr == nil && serverInfo.Code != tt.code {
				t.Errorf("expected server auth code %v, got %v", tt.code, serverInfo.Code)
			}
		})
	}
}
