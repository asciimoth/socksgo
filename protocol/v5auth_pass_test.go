package protocol_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
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
		{
			name:      "TooLongUser",
			user:      string(make([]byte, 512)),
			pass:      "",
			verifyFn:  defaultVerify,
			clientErr: fmt.Errorf("too long username: 512 bytes"),
			serverErr: fmt.Errorf("EOF"),
		},
		{
			name:      "TooLongPass",
			user:      "",
			pass:      string(make([]byte, 512)),
			verifyFn:  defaultVerify,
			clientErr: fmt.Errorf("too long password: 512 bytes"),
			serverErr: fmt.Errorf("EOF"),
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

			clientInfo, serverInfo, clientErr, serverErr := runPassAuthTest(
				method,
				handler,
				pool,
			)

			if fmt.Sprintf("%s", clientErr) != fmt.Sprintf("%s", tt.clientErr) {
				t.Errorf(
					"client err %s while expected %s",
					clientErr,
					tt.clientErr,
				)
			}
			if fmt.Sprintf("%s", serverErr) != fmt.Sprintf("%s", tt.serverErr) {
				t.Errorf(
					"server err %s while expected %s",
					serverErr,
					tt.serverErr,
				)
			}

			if clientErr == nil {
				if clientInfo.Code != protocol.PassAuthCode {
					t.Errorf(
						"expected client auth code %v, got %v",
						protocol.PassAuthCode,
						clientInfo.Code,
					)
				}
				if _, v := protocol.GetAuthParam[string](
					clientInfo,
					"user",
				); v != user {
					t.Errorf("expected client user %v, got %v", user, v)
				}
				if _, v := protocol.GetAuthParam[string](
					clientInfo,
					"pass",
				); v != pass {
					t.Errorf("expected client pass %v, got %v", user, v)
				}
			}
			if serverErr == nil {
				if serverInfo.Code != protocol.PassAuthCode {
					t.Errorf(
						"expected server auth code %v, got %v",
						protocol.PassAuthCode,
						serverInfo.Code,
					)
				}
				if _, v := protocol.GetAuthParam[string](
					serverInfo,
					"user",
				); v != user {
					t.Errorf("expected server user %v, got %v", user, v)
				}
				if _, v := protocol.GetAuthParam[string](
					serverInfo,
					"pass",
				); v != pass {
					t.Errorf("expected server pass %v, got %v", user, v)
				}
			}
		})
	}
}

func TestPassAuthNaming(t *testing.T) {
	method := (&protocol.PassAuthMethod{}).Name()
	handler := (&protocol.PassAuthHandler{}).Name()

	if method != "user-pass auth" || handler != "user-pass auth" {
		t.Fatal(method, handler)
	}
}

func TestPassAuthMethodBadConn(t *testing.T) {
	t.Run("Closed Conn", func(t *testing.T) {
		a, b := net.Pipe()
		_ = a.Close()
		_ = b.Close()
		method := &protocol.PassAuthMethod{}
		_, _, err := method.RunAuth(a, nil)
		if err.Error() != "io: read/write on closed pipe" {
			t.Fatalf(
				"got %s while expecting io: read/write on closed pipe",
				err,
			)
		}
	})
	t.Run("Closed Conn after 1 byte", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			_, _ = b.Write([]byte{0})
			_ = b.Close()
		}()
		go func() {
			for {
				_, err := b.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		method := &protocol.PassAuthMethod{}
		_, _, err := method.RunAuth(a, nil)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
	t.Run("Wrong version", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			_, _ = b.Write([]byte{42, 42})
			_ = b.Close()
		}()
		go func() {
			for {
				_, err := b.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		method := &protocol.PassAuthMethod{}
		_, _, err := method.RunAuth(a, nil)
		if err.Error() != "unknown user+pass auth version 42" {
			t.Fatalf(
				"got %s while expecting unknown user+pass auth version 42",
				err,
			)
		}
	})
}

func TestPassAuthHandlerBadConn(t *testing.T) {
	t.Run("Closed Conn", func(t *testing.T) {
		a, b := net.Pipe()
		_ = a.Close()
		_ = b.Close()
		handler := &protocol.PassAuthHandler{}
		_, _, err := handler.HandleAuth(a, nil)
		if err.Error() != "io: read/write on closed pipe" {
			t.Fatalf(
				"got %s while expecting io: read/write on closed pipe",
				err,
			)
		}
	})
	t.Run("Closed Conn after 1 byte", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			_, _ = b.Write([]byte{0})
			_ = b.Close()
		}()
		go func() {
			for {
				_, err := b.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		handler := &protocol.PassAuthHandler{}
		_, _, err := handler.HandleAuth(a, nil)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
	t.Run("Fail read user", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{1, 42, 0}))
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
		handler := &protocol.PassAuthHandler{}
		_, _, err := handler.HandleAuth(a, nil)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
	t.Run("Fail read pass", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{1, 1, 42, 42, 0}))
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
		handler := &protocol.PassAuthHandler{}
		_, _, err := handler.HandleAuth(a, nil)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
	t.Run("Wrong version", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			_, _ = b.Write([]byte{42, 42})
			_ = b.Close()
		}()
		go func() {
			for {
				_, err := b.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		handler := &protocol.PassAuthHandler{}
		_, _, err := handler.HandleAuth(a, nil)
		if err.Error() != "unknown user+pass auth version 42" {
			t.Fatalf(
				"got %s while expecting unknown user+pass auth version 42",
				err,
			)
		}
	})
}
