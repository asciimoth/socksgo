package main

import (
	"bytes"
	"net"
	"testing"
)

func TestCustomAuthHandlerHandleAuth(t *testing.T) {
	tests := []struct {
		name      string
		token     []byte
		wantReply byte
		wantErr   bool
	}{
		{
			name:      "valid",
			token:     hashToken("secret"),
			wantReply: 0,
			wantErr:   false,
		},
		{
			name:      "short invalid",
			token:     []byte{1, 2, 3},
			wantReply: 1,
			wantErr:   true,
		},
		{
			name:      "same length invalid",
			token:     hashToken("wrong"),
			wantReply: 1,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer func() {
				_ = c1.Close()
				_ = c2.Close()
			}()

			errCh := make(chan error, 1)
			go func() {
				handler := &CustomAuthHandler{
					ExpectedToken: hashToken("secret"),
				}
				_, _, err := handler.HandleAuth(c1, nil)
				errCh <- err
			}()

			frame := append([]byte{byte(len(tc.token))}, tc.token...)
			if _, err := c2.Write(frame); err != nil {
				t.Fatal(err)
			}

			reply := []byte{0xff}
			if _, err := c2.Read(reply); err != nil {
				t.Fatal(err)
			}
			if reply[0] != tc.wantReply {
				t.Fatalf("reply = %d, want %d", reply[0], tc.wantReply)
			}

			err := <-errCh
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestHashTokenReturnsBytes(t *testing.T) {
	got := hashToken("secret")
	if len(got) != 32 {
		t.Fatalf("hash length = %d, want 32", len(got))
	}
	if bytes.Equal(got, []byte("secret")) {
		t.Fatal("hash must not equal raw token")
	}
}
