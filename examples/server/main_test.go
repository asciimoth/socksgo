package main

import (
	"reflect"
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

func TestBuildAuthHandlers(t *testing.T) {
	tests := []struct {
		name string
		user string
		pass string
		want bool
	}{
		{name: "empty", want: false},
		{name: "user only", user: "alice", want: false},
		{name: "pass only", pass: "secret", want: false},
		{name: "both", user: "alice", pass: "secret", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auth := buildAuthHandlers(tc.user, tc.pass)
			if tc.want != (auth != nil) {
				t.Fatalf("auth exists = %v, want %v", auth != nil, tc.want)
			}
			if !tc.want {
				return
			}

			if auth.Get(protocol.NoAuthCode) != nil {
				t.Fatal("no-auth must not be configured with credentials")
			}

			handler, ok := auth.Get(protocol.PassAuthCode).(*protocol.PassAuthHandler)
			if !ok {
				t.Fatal("password auth handler expected")
			}
			if !handler.VerifyFn("alice", "secret") {
				t.Fatal("correct credentials rejected")
			}
			if handler.VerifyFn("alice", "wrong") {
				t.Fatal("wrong password accepted")
			}
		})
	}
}

func TestBuildWSAcceptOptions(t *testing.T) {
	if buildWSAcceptOptions("") != nil {
		t.Fatal("empty patterns must use websocket defaults")
	}

	opts := buildWSAcceptOptions("https://a.example, https://b.example ")
	if opts == nil {
		t.Fatal("options expected")
	}
	want := []string{"https://a.example", "https://b.example"}
	if !reflect.DeepEqual(opts.OriginPatterns, want) {
		t.Fatalf("OriginPatterns = %v, want %v", opts.OriginPatterns, want)
	}
}
