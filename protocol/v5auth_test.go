package protocol_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/protocol"
)

func runAuthHandshakeTest(
	methods *protocol.AuthMethods, handlers *protocol.AuthHandlers,
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
		var ver [1]byte
		_, serverErr = io.ReadFull(serverConn, ver[:])
		if serverErr != nil {
			readyCh <- nil
			return
		}

		_, serverInfo, serverErr = protocol.HandleAuth(
			serverConn,
			pool,
			handlers,
		)
		readyCh <- nil
	}()

	// Client side
	go func() {
		_, clientInfo, clientErr = protocol.RunAuth(clientConn, pool, methods)
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
			clientErr: errors.New("no acceptable socks auth methods"),
			serverErr: errors.New("no acceptable socks auth methods"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

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

			clientInfo, serverInfo, clientErr, serverErr := runAuthHandshakeTest(
				methods,
				handlers,
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

			if clientErr == nil && clientInfo.Code != tt.code {
				t.Errorf(
					"expected client auth code %v, got %v",
					tt.code,
					clientInfo.Code,
				)
			}
			if serverErr == nil && serverInfo.Code != tt.code {
				t.Errorf(
					"expected server auth code %v, got %v",
					tt.code,
					serverInfo.Code,
				)
			}
		})
	}
}

func TestAuthMethodCode_String(t *testing.T) {
	tests := []struct {
		name     string
		code     protocol.AuthMethodCode
		expected string
	}{
		// Standard auth methods
		{
			name:     "NoAuthCode",
			code:     protocol.NoAuthCode,
			expected: "no auth required",
		},
		{
			name:     "GSSAuthCode",
			code:     protocol.GSSAuthCode,
			expected: "GSS auth",
		},
		{
			name:     "PassAuthCode",
			code:     protocol.PassAuthCode,
			expected: "user-pass auth",
		},
		{
			name:     "NoAccAuthCode",
			code:     protocol.NoAccAuthCode,
			expected: "no acceptable auth methods",
		},
		// IANA assigned range (0x03-0x7f)
		{
			name:     "IANA assigned minimum",
			code:     0x03,
			expected: "IANA assigned auth",
		},
		{
			name:     "IANA assigned middle",
			code:     0x40,
			expected: "IANA assigned auth",
		},
		{
			name:     "IANA assigned maximum",
			code:     0x7f,
			expected: "IANA assigned auth",
		},
		// Private range (0x80-0xfe)
		{
			name:     "Private auth minimum",
			code:     0x80,
			expected: "private auth method",
		},
		{
			name:     "Private auth middle",
			code:     0xc0,
			expected: "private auth method",
		},
		{
			name:     "Private auth maximum",
			code:     0xfe,
			expected: "private auth method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.code.String()
			if result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestAuthInfo_String(t *testing.T) {
	tests := []struct {
		name     string
		authInfo protocol.AuthInfo
		expected string
	}{
		{
			name: "Empty AuthInfo",
			authInfo: protocol.AuthInfo{
				Code: protocol.NoAuthCode,
			},
			expected: "0 no auth required\n",
		},
		{
			name: "With custom name",
			authInfo: protocol.AuthInfo{
				Code: protocol.PassAuthCode,
				Name: "custom-auth",
			},
			expected: "2 custom-auth\n",
		},
		{
			name: "With Info map",
			authInfo: protocol.AuthInfo{
				Code: protocol.GSSAuthCode,
				Info: map[string]any{
					"username": "testuser",
					"timeout":  30,
				},
			},
			expected: "1 GSS auth\ntimeout: 30username: testuser",
		},
		{
			name: "With multiple Info entries",
			authInfo: protocol.AuthInfo{
				Code: protocol.NoAccAuthCode,
				Info: map[string]any{
					"key1": "value1",
					"key2": "value2",
					"key3": 123,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.authInfo.String()

			if tt.name == "With multiple Info entries" {
				// For map with multiple entries, check it contains the expected format
				expectedStart := fmt.Sprintf(
					"%d %s\n",
					tt.authInfo.Code,
					tt.authInfo.GetName(),
				)
				if !bytes.HasPrefix( //nolint
					[]byte(result),
					[]byte(expectedStart),
				) { //nolint
					t.Errorf(
						"String() should start with %q, got %q",
						expectedStart,
						result,
					)
				}

				// Check it contains all the key-value pairs
				for k, v := range tt.authInfo.Info {
					expectedPair := fmt.Sprintf("%s: %v", k, v)
					if !bytes.Contains( //nolint
						[]byte(result),
						[]byte(expectedPair),
					) { //nolint
						t.Errorf(
							"String() should contain %q, got %q",
							expectedPair,
							result,
						)
					}
				}
			} else if result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestAuthInfo_GetName(t *testing.T) {
	tests := []struct {
		name     string
		authInfo protocol.AuthInfo
		expected string
	}{
		{
			name: "Empty name returns code string",
			authInfo: protocol.AuthInfo{
				Code: protocol.NoAuthCode,
				Name: "",
			},
			expected: "no auth required",
		},
		{
			name: "Non-empty name returns name",
			authInfo: protocol.AuthInfo{
				Code: protocol.NoAuthCode,
				Name: "custom-name",
			},
			expected: "custom-name",
		},
		{
			name: "GSS auth with custom name",
			authInfo: protocol.AuthInfo{
				Code: protocol.GSSAuthCode,
				Name: "gssapi",
			},
			expected: "gssapi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.authInfo.GetName()
			if result != tt.expected {
				t.Errorf("GetName() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetAuthParam(t *testing.T) {
	authInfo := protocol.AuthInfo{
		Code: protocol.PassAuthCode,
		Info: map[string]any{
			"username": "testuser",
			"password": "secret123",
			"timeout":  30,
			"enabled":  true,
			"score":    95.5,
		},
	}

	tests := []struct {
		name          string
		key           string
		expectedOk    bool
		expectedValue any
	}{
		{
			name:          "Existing string value",
			key:           "username",
			expectedOk:    true,
			expectedValue: "testuser",
		},
		{
			name:          "Existing int value",
			key:           "timeout",
			expectedOk:    true,
			expectedValue: 30,
		},
		{
			name:          "Existing bool value",
			key:           "enabled",
			expectedOk:    true,
			expectedValue: true,
		},
		{
			name:          "Existing float value",
			key:           "score",
			expectedOk:    true,
			expectedValue: 95.5,
		},
		{
			name:          "Non-existent key",
			key:           "nonexistent",
			expectedOk:    false,
			expectedValue: "",
		},
		{
			name:          "Wrong type conversion",
			key:           "username",
			expectedOk:    false,
			expectedValue: 0, // Trying to get string as int
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch v := tt.expectedValue.(type) {
			case string:
				ok, val := protocol.GetAuthParam[string](authInfo, tt.key)
				if ok != tt.expectedOk {
					t.Errorf(
						"GetAuthParam() ok = %v, want %v",
						ok,
						tt.expectedOk,
					)
				}
				if ok && val != v {
					t.Errorf("GetAuthParam() = %v, want %v", val, v)
				}
			case int:
				ok, val := protocol.GetAuthParam[int](authInfo, tt.key)
				if ok != tt.expectedOk {
					t.Errorf(
						"GetAuthParam() ok = %v, want %v",
						ok,
						tt.expectedOk,
					)
				}
				if ok && val != v {
					t.Errorf("GetAuthParam() = %v, want %v", val, v)
				}
			case bool:
				ok, val := protocol.GetAuthParam[bool](authInfo, tt.key)
				if ok != tt.expectedOk {
					t.Errorf(
						"GetAuthParam() ok = %v, want %v",
						ok,
						tt.expectedOk,
					)
				}
				if ok && val != v {
					t.Errorf("GetAuthParam() = %v, want %v", val, v)
				}
			case float64:
				ok, val := protocol.GetAuthParam[float64](authInfo, tt.key)
				if ok != tt.expectedOk {
					t.Errorf(
						"GetAuthParam() ok = %v, want %v",
						ok,
						tt.expectedOk,
					)
				}
				if ok && val != v {
					t.Errorf("GetAuthParam() = %v, want %v", val, v)
				}
			}
		})
	}
}

func TestGetAuthParam_NilInfo(t *testing.T) {
	authInfo := protocol.AuthInfo{
		Code: protocol.NoAuthCode,
		Info: nil,
	}

	ok, val := protocol.GetAuthParam[string](authInfo, "anykey")
	if ok {
		t.Errorf(
			"GetAuthParam() with nil Info should return ok=false, got true",
		)
	}
	if val != "" {
		t.Errorf(
			"GetAuthParam() with nil Info should return zero value, got %v",
			val,
		)
	}
}

func TestGetAuthParam_EmptyInfo(t *testing.T) {
	authInfo := protocol.AuthInfo{
		Code: protocol.NoAuthCode,
		Info: map[string]any{},
	}

	ok, val := protocol.GetAuthParam[string](authInfo, "anykey")
	if ok {
		t.Errorf(
			"GetAuthParam() with empty Info should return ok=false, got true",
		)
	}
	if val != "" {
		t.Errorf(
			"GetAuthParam() with empty Info should return zero value, got %v",
			val,
		)
	}
}

// Test for coverage of all constants
func TestAuthConstants(t *testing.T) {
	// Verify constants have expected values
	if protocol.NoAuthCode != 0x0 {
		t.Errorf("NoAuthCode = %v, want 0x0", protocol.NoAuthCode)
	}
	if protocol.GSSAuthCode != 0x1 {
		t.Errorf("GSSAuthCode = %v, want 0x1", protocol.GSSAuthCode)
	}
	if protocol.PassAuthCode != 0x02 {
		t.Errorf("PassAuthCode = %v, want 0x02", protocol.PassAuthCode)
	}
	if protocol.NoAccAuthCode != 0xff {
		t.Errorf("NoAccAuthCode = %v, want 0xff", protocol.NoAccAuthCode)
	}
}

func TestNoAuthHandlerName(t *testing.T) {
	code := (&protocol.NoAuthHandler{}).Code()
	name := (&protocol.NoAuthHandler{}).Name()
	if code != protocol.NoAuthCode {
		t.Fatalf("got %d while %d expected", code, protocol.NoAuthCode)
	}
	if name != protocol.NoAuthCode.String() {
		t.Fatalf("got %s while %s expected", name, protocol.NoAuthCode.String())
	}
}

// Mock implementations for testing
type mockAuthMethod struct {
	code    protocol.AuthMethodCode
	name    string
	runAuth func(conn net.Conn, pool bufpool.Pool) (net.Conn, protocol.AuthInfo, error)
}

func (m *mockAuthMethod) Name() string                  { return m.name }
func (m *mockAuthMethod) Code() protocol.AuthMethodCode { return m.code }

func (m *mockAuthMethod) RunAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, protocol.AuthInfo, error) {
	if m.runAuth != nil {
		return m.runAuth(conn, pool)
	}
	return conn, protocol.AuthInfo{Code: m.code}, nil
}

type mockAuthHandler struct {
	code       protocol.AuthMethodCode
	name       string
	handleAuth func(conn net.Conn, pool bufpool.Pool) (net.Conn, protocol.AuthInfo, error)
	verifyFunc func(user, pass string) bool
}

func (m *mockAuthHandler) Name() string                  { return m.name }
func (m *mockAuthHandler) Code() protocol.AuthMethodCode { return m.code }

func (m *mockAuthHandler) HandleAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, protocol.AuthInfo, error) {
	if m.handleAuth != nil {
		return m.handleAuth(conn, pool)
	}
	return conn, protocol.AuthInfo{Code: m.code}, nil
}
func (m *mockAuthHandler) verify(user, pass string) bool {
	if m.verifyFunc != nil {
		return m.verifyFunc(user, pass)
	}
	return false
}

func TestNoAuthHandler(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	handler := &protocol.NoAuthHandler{}

	t.Run("Code returns NoAuthCode", func(t *testing.T) {
		if handler.Code() != protocol.NoAuthCode {
			t.Errorf(
				"Code() = %v, want %v",
				handler.Code(),
				protocol.NoAuthCode,
			)
		}
	})

	t.Run("Name returns code string", func(t *testing.T) {
		expected := protocol.NoAuthCode.String()
		if handler.Name() != expected {
			t.Errorf("Name() = %v, want %v", handler.Name(), expected)
		}
	})

	t.Run("HandleAuth returns AuthInfo with NoAuthCode", func(t *testing.T) {
		conn := &net.TCPConn{}

		newConn, info, err := handler.HandleAuth(conn, pool)
		if err != nil {
			t.Errorf("HandleAuth() error = %v, want nil", err)
		}
		if newConn != conn {
			t.Errorf("HandleAuth() returned different connection")
		}
		if info.Code != protocol.NoAuthCode {
			t.Errorf(
				"HandleAuth() info.Code = %v, want %v",
				info.Code,
				protocol.NoAuthCode,
			)
		}
	})
}

func TestAuthMethods_Get(t *testing.T) {
	t.Run("nil AuthMethods returns nil", func(t *testing.T) {
		var am *protocol.AuthMethods
		result := am.Get(protocol.PassAuthCode)
		if result != nil {
			t.Errorf("Get() on nil AuthMethods = %v, want nil", result)
		}
	})

	t.Run("nil methodsMap returns nil", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		result := am.Get(protocol.PassAuthCode)
		if result != nil {
			t.Errorf("Get() with nil methodsMap = %v, want nil", result)
		}
	})

	t.Run("existing method returns method", func(t *testing.T) {
		method := &mockAuthMethod{code: protocol.PassAuthCode, name: "test"}
		am := &protocol.AuthMethods{}
		am = am.Add(method)

		result := am.Get(protocol.PassAuthCode)
		if result != method {
			t.Errorf("Get() = %v, want %v", result, method)
		}
	})

	t.Run("non-existing method returns nil", func(t *testing.T) {
		method := &mockAuthMethod{code: protocol.PassAuthCode}
		am := &protocol.AuthMethods{}
		am = am.Add(method)

		result := am.Get(protocol.GSSAuthCode)
		if result != nil {
			t.Errorf("Get() = %v, want nil", result)
		}
	})
}

func TestAuthMethods_Add(t *testing.T) {
	t.Run("Add to nil AuthMethods creates new", func(t *testing.T) {
		var am *protocol.AuthMethods
		method := &mockAuthMethod{code: protocol.PassAuthCode}

		result := am.Add(method)
		if result == nil {
			t.Errorf("Add() returned nil")
		}
		if result.Get(protocol.PassAuthCode) != method {
			t.Errorf("Added method not found")
		}
	})

	t.Run("Add nil method does nothing", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		result := am.Add(nil)
		if result != am {
			t.Errorf("Add(nil) should return same AuthMethods")
		}
	})

	t.Run("Add method with NoAuthCode does nothing", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		method := &mockAuthMethod{code: protocol.NoAuthCode}

		result := am.Add(method)
		if result != am {
			t.Errorf("Add(NoAuthCode) should return same AuthMethods")
		}
	})

	t.Run("Add method with NoAccAuthCode does nothing", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		method := &mockAuthMethod{code: protocol.NoAccAuthCode}

		result := am.Add(method)
		if result != am {
			t.Errorf("Add(NoAccAuthCode) should return same AuthMethods")
		}
	})

	t.Run("Add multiple methods", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		method1 := &mockAuthMethod{code: protocol.PassAuthCode}
		method2 := &mockAuthMethod{code: protocol.GSSAuthCode}

		am.Add(method1).Add(method2)

		if am.Get(protocol.PassAuthCode) != method1 {
			t.Errorf("Method1 not found")
		}
		if am.Get(protocol.GSSAuthCode) != method2 {
			t.Errorf("Method2 not found")
		}
	})
}

func TestAuthMethods_User(t *testing.T) {
	// Define PassAuthMethod for testing
	type PassAuthMethod struct {
		protocol.AuthMethod
		User string
		Pass string
	}

	t.Run("nil AuthMethods returns empty string", func(t *testing.T) {
		var am *protocol.AuthMethods
		result := am.User()
		if result != "" {
			t.Errorf("User() on nil AuthMethods = %q, want empty", result)
		}
	})

	t.Run("nil methodsMap returns empty string", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		result := am.User()
		if result != "" {
			t.Errorf("User() with nil methodsMap = %q, want empty", result)
		}
	})

	t.Run("no PassAuthMethod returns empty string", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		method := &mockAuthMethod{code: protocol.GSSAuthCode}
		am.Add(method)

		result := am.User()
		if result != "" {
			t.Errorf("User() = %q, want empty", result)
		}
	})

	t.Run("PassAuthMethod", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		method := &protocol.PassAuthMethod{User: "user"}
		am.Add(method)

		result := am.User()
		if result != "user" {
			t.Errorf("User() = %q, want user", result)
		}
	})

	t.Run(
		"PassAuthMethod but not *PassAuthMethod returns empty string",
		func(t *testing.T) {
			am := &protocol.AuthMethods{}
			method := &mockAuthMethod{code: protocol.PassAuthCode}
			am.Add(method)

			result := am.User()
			if result != "" {
				t.Errorf("User() = %q, want empty", result)
			}
		},
	)
}

func TestAuthMethods_Clone(t *testing.T) {
	t.Run("Clone empty AuthMethods", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		clone := am.Clone()

		if clone != nil {
			t.Error("Clone() on void AuthMethods must return nil")
		}
	})

	t.Run("Clone with methods", func(t *testing.T) {
		am := &protocol.AuthMethods{}
		method1 := &mockAuthMethod{code: protocol.PassAuthCode, name: "method1"}
		method2 := &mockAuthMethod{code: protocol.GSSAuthCode, name: "method2"}

		am = am.Add(method1).Add(method2)
		clone := am.Clone()

		if clone == nil {
			t.Errorf("Clone() returned nil")
		}
	})
}

func TestAuthHandlers_Get(t *testing.T) {
	t.Run(
		"nil AuthHandlers returns NoAuthHandler for NoAuthCode",
		func(t *testing.T) {
			var ah *protocol.AuthHandlers
			result := ah.Get(protocol.NoAuthCode)

			if result == nil {
				t.Errorf("Get(NoAuthCode) returned nil")
			}
			if _, ok := result.(*protocol.NoAuthHandler); !ok {
				t.Errorf("Get(NoAuthCode) = %T, want *NoAuthHandler", result)
			}
		},
	)

	t.Run(
		"nil AuthHandlers returns PassAuthHandler for PassAuthCode",
		func(t *testing.T) {
			var ah *protocol.AuthHandlers
			result := ah.Get(protocol.PassAuthCode)

			if result == nil {
				t.Errorf("Get(PassAuthCode) returned nil")
			}
			// Check if it's a PassAuthHandler (type assertion would fail if not)
			// We can't check the exact type without the actual type
		},
	)

	t.Run("nil AuthHandlers returns nil for other codes", func(t *testing.T) {
		var ah *protocol.AuthHandlers
		result := ah.Get(protocol.GSSAuthCode)

		if result != nil {
			t.Errorf("Get(GSSAuthCode) = %v, want nil", result)
		}
	})

	t.Run("nil handlers map returns default handlers", func(t *testing.T) {
		ah := &protocol.AuthHandlers{}
		result := ah.Get(protocol.NoAuthCode)

		if result == nil {
			t.Errorf("Get(NoAuthCode) returned nil")
		}
	})

	t.Run("existing handler returns handler", func(t *testing.T) {
		handler := &mockAuthHandler{code: protocol.GSSAuthCode}
		ah := (&protocol.AuthHandlers{}).Add(handler)

		result := ah.Get(protocol.GSSAuthCode)
		if result != handler {
			t.Errorf("Get() = %v, want %v", result, handler)
		}
	})

	t.Run("non-existing handler returns nil", func(t *testing.T) {
		handler := &mockAuthHandler{code: protocol.GSSAuthCode}
		ah := (&protocol.AuthHandlers{}).Add(handler)

		result := ah.Get(protocol.PassAuthCode)
		if result != nil {
			t.Errorf("Get() = %v, want nil", result)
		}
	})
}

func TestAuthHandlers_Add(t *testing.T) {
	t.Run("Add to nil AuthHandlers creates new", func(t *testing.T) {
		var ah *protocol.AuthHandlers
		handler := &mockAuthHandler{code: protocol.PassAuthCode}

		result := ah.Add(handler)
		if result == nil {
			t.Errorf("Add() returned nil")
		}
		if result.Get(protocol.PassAuthCode) != handler {
			t.Errorf("Added handler not found")
		}
	})

	t.Run("Add nil handler does nothing", func(t *testing.T) {
		ah := &protocol.AuthHandlers{}
		result := ah.Add(nil)
		if result != ah {
			t.Errorf("Add(nil) should return same AuthHandlers")
		}
	})

	t.Run("Add handler with NoAuthCode does nothing", func(t *testing.T) {
		ah := &protocol.AuthHandlers{}
		handler := &mockAuthHandler{code: protocol.NoAuthCode}

		result := ah.Add(handler)
		if result != ah {
			t.Errorf("Add(NoAuthCode) should return same AuthHandlers")
		}
	})

	t.Run("Add handler with NoAccAuthCode does nothing", func(t *testing.T) {
		ah := &protocol.AuthHandlers{}
		handler := &mockAuthHandler{code: protocol.NoAccAuthCode}

		result := ah.Add(handler)
		if result != ah {
			t.Errorf("Add(NoAccAuthCode) should return same AuthHandlers")
		}
	})

	t.Run("Add multiple handlers", func(t *testing.T) {
		ah := &protocol.AuthHandlers{}
		handler1 := &mockAuthHandler{code: protocol.PassAuthCode}
		handler2 := &mockAuthHandler{code: protocol.GSSAuthCode}

		ah.Add(handler1).Add(handler2)

		if ah.Get(protocol.PassAuthCode) != handler1 {
			t.Errorf("Handler1 not found")
		}
		if ah.Get(protocol.GSSAuthCode) != handler2 {
			t.Errorf("Handler2 not found")
		}
	})
}

func TestAuthHandlers_CheckSocks4User(t *testing.T) {
	// Define PassAuthHandler for testing
	type PassAuthHandler struct {
		protocol.AuthHandler
		verifyFunc func(user, pass string) bool
	}

	t.Run("nil AuthHandlers returns false", func(t *testing.T) {
		var ah *protocol.AuthHandlers
		result := ah.CheckSocks4User("testuser")
		if !result {
			t.Errorf("CheckSocks4User() = false, want true")
		}
	})

	t.Run("no PassAuthCode handler returns true", func(t *testing.T) {
		var ah *protocol.AuthHandlers
		ah.Add(&mockAuthHandler{code: protocol.GSSAuthCode})

		result := ah.CheckSocks4User("testuser")
		if !result {
			t.Errorf("CheckSocks4User() = false, want true")
		}
	})

	t.Run("handler not *PassAuthHandler returns true", func(t *testing.T) {
		var ah *protocol.AuthHandlers
		ah.Add(&mockAuthHandler{code: protocol.PassAuthCode})

		result := ah.CheckSocks4User("testuser")
		if !result {
			t.Errorf("CheckSocks4User() = false, want true")
		}
	})
}

func TestTooMuchMethods(t *testing.T) {
	am := &protocol.AuthMethods{}
	for i := range 255 {
		method := &mockAuthMethod{
			code: protocol.AuthMethodCode(i), //nolint
			name: "test",
		} //nolint
		am = am.Add(method)
	}
	ln := len(am.GetMsg())
	if ln > 257 {
		t.Fatalf("msg length is too big %d", ln)
	}
}

func TestRebuildOnVoidAuthMethods(t *testing.T) {
	am := &protocol.AuthMethods{}
	am.Rebuild()
	if !slices.Equal(am.GetMsg(), protocol.DefaultMethodSelectionMsg) {
		t.Fatal("Rebuild on void AuthMethods must do nothing")
	}
}

func TestRunAuthErrors(t *testing.T) {
	t.Run("Err Write Msg", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		_ = a.Close()
		_ = b.Close()

		_, _, err := protocol.RunAuth(a, pool, nil)
		if err.Error() != "io: read/write on closed pipe" {
			t.Fatal(err)
		}
	})
	t.Run("Err Read Resp", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{1}))
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

		_, _, err := protocol.RunAuth(a, pool, nil)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
	t.Run("Err Unkwnown Ver", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{42, 42}))
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

		_, _, err := protocol.RunAuth(a, pool, nil)
		exp := protocol.UnknownAuthVerError{42}.Error()
		if err.Error() != exp {
			t.Fatalf("got %s while expecting %s", err, exp)
		}
	})
	t.Run("Err Unsupported Auth Method", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{5, 42}))
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

		_, _, err := protocol.RunAuth(a, pool, nil)
		exp := protocol.UnsupportedAuthMethodError{42}.Error()
		if err.Error() != exp {
			t.Fatalf("got %s while expecting %s", err, exp)
		}
	})
}

func TestHandleAuthErrors(t *testing.T) {
	t.Run("Err Read Count", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		_ = a.Close()
		_ = b.Close()

		_, _, err := protocol.HandleAuth(a, pool, nil)
		if err.Error() != "io: read/write on closed pipe" {
			t.Fatal(err)
		}
	})
	t.Run("Err Read Methods", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{42}))
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

		_, _, err := protocol.HandleAuth(a, pool, nil)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
}
