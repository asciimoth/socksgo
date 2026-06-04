package socksgo

import "github.com/xtaci/smux"

func withDefaultSmuxConfig(config *smux.Config) *smux.Config {
	defaults := smux.DefaultConfig()
	if config == nil {
		return defaults
	}

	cfg := *config
	if cfg.Version == 0 {
		cfg.Version = defaults.Version
	}
	if !cfg.KeepAliveDisabled {
		if cfg.KeepAliveInterval == 0 {
			cfg.KeepAliveInterval = defaults.KeepAliveInterval
		}
		if cfg.KeepAliveTimeout == 0 {
			cfg.KeepAliveTimeout = defaults.KeepAliveTimeout
		}
	}
	if cfg.MaxFrameSize == 0 {
		cfg.MaxFrameSize = defaults.MaxFrameSize
	}
	if cfg.MaxReceiveBuffer == 0 {
		cfg.MaxReceiveBuffer = defaults.MaxReceiveBuffer
	}
	if cfg.MaxStreamBuffer == 0 {
		cfg.MaxStreamBuffer = defaults.MaxStreamBuffer
	}
	return &cfg
}
