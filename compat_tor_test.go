////go:build tor

package socksgo_test

import "testing"

func TestIntegrationWithTor(t *testing.T) {
	cfg := GetEnvConfig()

	c5 := buildClient("socks5://"+cfg.Tor+"?tor", t)
	c4a := buildClient("socks4a://"+cfg.Tor+"?tor", t)

	t.Run("HttpRequest", func(t *testing.T) {
		testDial(c5, t, cfg.Pairs...)
		testDial(c4a, t, cfg.Pairs...)
	})

	t.Run("Lookup", func(t *testing.T) {
		testLookup(c5, t, true, cfg.Pairs...)
		testLookup(c4a, t, false, cfg.Pairs...)
	})
}
