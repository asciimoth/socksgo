// nolint
package socksgo

import (
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestWithDefaultSmuxConfigNil(t *testing.T) {
	cfg := withDefaultSmuxConfig(nil)
	defaults := smux.DefaultConfig()

	if cfg == nil {
		t.Fatal("config is nil")
	}
	if cfg.KeepAliveDisabled {
		t.Fatal("keepalive is disabled")
	}
	if cfg.KeepAliveInterval != defaults.KeepAliveInterval {
		t.Fatalf(
			"keepalive interval mismatch: want %v got %v",
			defaults.KeepAliveInterval,
			cfg.KeepAliveInterval,
		)
	}
	if cfg.KeepAliveTimeout != defaults.KeepAliveTimeout {
		t.Fatalf(
			"keepalive timeout mismatch: want %v got %v",
			defaults.KeepAliveTimeout,
			cfg.KeepAliveTimeout,
		)
	}
}

func TestWithDefaultSmuxConfigPartial(t *testing.T) {
	original := &smux.Config{
		MaxFrameSize: 4096,
	}
	cfg := withDefaultSmuxConfig(original)
	defaults := smux.DefaultConfig()

	if cfg == original {
		t.Fatal("config was not copied")
	}
	if original.Version != 0 {
		t.Fatal("original config was mutated")
	}
	if cfg.Version != defaults.Version {
		t.Fatalf(
			"version mismatch: want %d got %d",
			defaults.Version,
			cfg.Version,
		)
	}
	if cfg.KeepAliveDisabled {
		t.Fatal("keepalive is disabled")
	}
	if cfg.KeepAliveInterval != defaults.KeepAliveInterval {
		t.Fatalf(
			"keepalive interval mismatch: want %v got %v",
			defaults.KeepAliveInterval,
			cfg.KeepAliveInterval,
		)
	}
	if cfg.KeepAliveTimeout != defaults.KeepAliveTimeout {
		t.Fatalf(
			"keepalive timeout mismatch: want %v got %v",
			defaults.KeepAliveTimeout,
			cfg.KeepAliveTimeout,
		)
	}
	if cfg.MaxFrameSize != original.MaxFrameSize {
		t.Fatalf(
			"max frame size mismatch: want %d got %d",
			original.MaxFrameSize,
			cfg.MaxFrameSize,
		)
	}
}

func TestWithDefaultSmuxConfigKeepaliveDisabled(t *testing.T) {
	original := &smux.Config{
		KeepAliveDisabled: true,
	}
	cfg := withDefaultSmuxConfig(original)

	if !cfg.KeepAliveDisabled {
		t.Fatal("keepalive is enabled")
	}
	if cfg.KeepAliveInterval != 0 {
		t.Fatalf(
			"keepalive interval mismatch: want 0 got %v",
			cfg.KeepAliveInterval,
		)
	}
	if cfg.KeepAliveTimeout != 0 {
		t.Fatalf(
			"keepalive timeout mismatch: want 0 got %v",
			cfg.KeepAliveTimeout,
		)
	}
	if err := smux.VerifyConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestWithDefaultSmuxConfigCustomKeepalive(t *testing.T) {
	original := &smux.Config{
		KeepAliveInterval: time.Second,
		KeepAliveTimeout:  2 * time.Second,
	}
	cfg := withDefaultSmuxConfig(original)

	if cfg.KeepAliveDisabled {
		t.Fatal("keepalive is disabled")
	}
	if cfg.KeepAliveInterval != original.KeepAliveInterval {
		t.Fatalf(
			"keepalive interval mismatch: want %v got %v",
			original.KeepAliveInterval,
			cfg.KeepAliveInterval,
		)
	}
	if cfg.KeepAliveTimeout != original.KeepAliveTimeout {
		t.Fatalf(
			"keepalive timeout mismatch: want %v got %v",
			original.KeepAliveTimeout,
			cfg.KeepAliveTimeout,
		)
	}
	if err := smux.VerifyConfig(cfg); err != nil {
		t.Fatal(err)
	}
}
