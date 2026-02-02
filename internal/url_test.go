package internal_test

import (
	"testing"

	"github.com/asciimoth/socksgo/internal"
)

func TestCheckURLBoolKey(t *testing.T) {
	t.Run("absent key", func(t *testing.T) {
		f, s := internal.CheckURLBoolKey(map[string][]string{}, "nope")
		if f || s {
			t.Fatalf("expected (false,false), got (%v,%v)", f, s)
		}
	})

	t.Run("nil slice", func(t *testing.T) {
		m := map[string][]string{"k": nil}
		f, s := internal.CheckURLBoolKey(m, "k")
		if !f || !s {
			t.Fatalf("expected (true,true) for nil slice, got (%v,%v)", f, s)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		m := map[string][]string{"k": {}}
		f, s := internal.CheckURLBoolKey(m, "k")
		if !f || !s {
			t.Fatalf("expected (true,true) for empty slice, got (%v,%v)", f, s)
		}
	})

	trueVals := []string{"true", "yes", "ok", "1", ""}
	for _, v := range trueVals {
		name := "val=" + v
		if v == "" {
			name = "val=emptystr"
		}
		t.Run(name, func(t *testing.T) {
			m := map[string][]string{"k": {v}}
			f, s := internal.CheckURLBoolKey(m, "k")
			if !f || !s {
				t.Fatalf("expected (true,true) for %q, got (%v,%v)", v, f, s)
			}
		})
	}

	t.Run("false value", func(t *testing.T) {
		m := map[string][]string{"k": {"no"}}
		f, s := internal.CheckURLBoolKey(m, "k")
		if f || !s {
			t.Fatalf("expected (false,true) for \"no\", got (%v,%v)", f, s)
		}
	})
}

func TestParseScheme(t *testing.T) {
	cases := []struct {
		in       string
		wantBase string
		wantTLS  bool
		wantWS   bool
	}{
		{"socks", "5", false, false},
		{"SOCKS5H", "5", false, false}, // only sets base via socks5h
		{"sockss", "5", true, false},
		{"socks4", "4", false, false},
		{"socks4s+ws", "4", true, true},
		{"socks4a", "4a", false, false},
		{"socks4as+wss", "4a", true, true},
		{"socks+tls+ws", "5", true, true},
		{"unknown", "", false, false},
	}

	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			base, tls, ws := internal.ParseScheme(c.in)
			if base != c.wantBase || tls != c.wantTLS || ws != c.wantWS {
				t.Fatalf(
					"parseScheme(%q) = (%q, %v, %v); want (%q, %v, %v)",
					c.in,
					base,
					tls,
					ws,
					c.wantBase,
					c.wantTLS,
					c.wantWS,
				)
			}
		})
	}
}
