////go:build tor

package socksgo_test

import (
	"testing"

	"github.com/asciimoth/bufpool"
)

func TestTorCompat(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	cfg := GetEnvConfig()

	c5 := buildClient("socks5://"+cfg.Tor+"?tor", t, pool)
	c4a := buildClient("socks4a://"+cfg.Tor+"?tor", t, pool)

	t.Run("HttpRequest", func(t *testing.T) {
		testDial(c5, t, cfg.Pairs...)
		testDial(c4a, t, cfg.Pairs...)
	})

	t.Run("Lookup", func(t *testing.T) {
		testLookup(c5, t, true, cfg.Pairs...)
		testLookup(c4a, t, false, cfg.Pairs...)
	})
}
