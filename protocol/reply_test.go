package protocol_test

import (
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

func TestReplyStatus_Ok(t *testing.T) {
	tests := []struct {
		name     string
		status   protocol.ReplyStatus
		expected bool
	}{
		{"Socks4 Granted", protocol.Granted, true},
		{"Socks5 SuccReply", protocol.SuccReply, true},
		{"Socks5 FailReply", protocol.FailReply, false},
		{"Socks4 Rejected", protocol.Rejected, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Ok(); got != tt.expected {
				t.Errorf("ReplyStatus.Ok() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestReplyStatus_String(t *testing.T) {
	tests := []struct {
		status   protocol.ReplyStatus
		expected string
	}{
		// SOCKS4
		{protocol.Granted, "request granted"},
		{protocol.Rejected, "request rejected or failed"},
		{
			protocol.IdentFailed,
			"request rejected because socks server cannot connect to identd on the client",
		},
		{
			protocol.IdentRequired,
			"request rejected because the client program and identd report different user-ids",
		},

		// SOCKS5
		{protocol.SuccReply, "succeeded"},
		{protocol.FailReply, "general SOCKS server failure"},
		{protocol.DisallowReply, "connection not allowed by ruleset"},
		{protocol.NetUnreachReply, "hetwork unreachable"},
		{protocol.HostUnreachReply, "host unreachable"},
		{protocol.ConnRefusedReply, "connection refused"},
		{protocol.TTLExpiredReply, "TTL expired"},
		{protocol.CmdNotSuppReply, "command not supported"},
		{protocol.AddrNotSuppReply, "address type not supported"},

		// Tor
		{protocol.TorDescNotFound, "onion service descriptor can not be found"},
		{protocol.TorDescInvalid, "onion service descriptor is invalid"},
		{protocol.TorIntroFail, "onion service introduction failed"},
		{protocol.TorRendFailed, "onion service rendezvous failed"},
		{protocol.TorMissAuth, "onion service missing client authorization"},
		{protocol.TorWrongAuth, "onion service wrong client authorization"},
		{protocol.TorInvalidAddr, "onion service invalid address"},
		{protocol.TorIntroTimeOut, "onion service introduction timed out"},

		// Unknown
		{protocol.ReplyStatus(0xff), "reply code no255"},
		{protocol.ReplyStatus(0x10), "reply code no16"},
	}

	for i, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.status.String(); got != tt.expected {
				t.Errorf(
					"test %d: ReplyStatus.String() = %v, want %v",
					i,
					got,
					tt.expected,
				)
			}
		})
	}
}

func TestReplyStatus_To5(t *testing.T) {
	tests := []struct {
		name     string
		status   protocol.ReplyStatus
		expected protocol.ReplyStatus
	}{
		// SOCKS4 conversions
		{"Granted to SuccReply", protocol.Granted, protocol.SuccReply},
		{"Rejected to FailReply", protocol.Rejected, protocol.FailReply},
		{"IdentFailed to FailReply", protocol.IdentFailed, protocol.FailReply},
		{
			"IdentRequired to FailReply",
			protocol.IdentRequired,
			protocol.FailReply,
		},

		// SOCKS5 should stay the same
		{"SuccReply stays", protocol.SuccReply, protocol.SuccReply},
		{"FailReply stays", protocol.FailReply, protocol.FailReply},
		{"DisallowReply stays", protocol.DisallowReply, protocol.DisallowReply},
		{
			"NetUnreachReply stays",
			protocol.NetUnreachReply,
			protocol.NetUnreachReply,
		},
		{
			"HostUnreachReply stays",
			protocol.HostUnreachReply,
			protocol.HostUnreachReply,
		},
		{
			"ConnRefusedReply stays",
			protocol.ConnRefusedReply,
			protocol.ConnRefusedReply,
		},
		{
			"TTLExpiredReply stays",
			protocol.TTLExpiredReply,
			protocol.TTLExpiredReply,
		},
		{
			"CmdNotSuppReply stays",
			protocol.CmdNotSuppReply,
			protocol.CmdNotSuppReply,
		},
		{
			"AddrNotSuppReply stays",
			protocol.AddrNotSuppReply,
			protocol.AddrNotSuppReply,
		},

		// Tor should stay the same
		{
			"TorDescNotFound stays",
			protocol.TorDescNotFound,
			protocol.TorDescNotFound,
		},
		{
			"TorDescInvalid stays",
			protocol.TorDescInvalid,
			protocol.TorDescInvalid,
		},
		{"TorIntroFail stays", protocol.TorIntroFail, protocol.TorIntroFail},
		{"TorRendFailed stays", protocol.TorRendFailed, protocol.TorRendFailed},
		{"TorMissAuth stays", protocol.TorMissAuth, protocol.TorMissAuth},
		{"TorWrongAuth stays", protocol.TorWrongAuth, protocol.TorWrongAuth},
		{
			"TorInvalidAddr stays",
			protocol.TorInvalidAddr,
			protocol.TorInvalidAddr,
		},
		{
			"TorIntroTimeOut stays",
			protocol.TorIntroTimeOut,
			protocol.TorIntroTimeOut,
		},

		// Unknown values
		{
			"Unknown stays",
			protocol.ReplyStatus(0xfa),
			protocol.ReplyStatus(0xfa),
		},
		{"Zero stays", protocol.ReplyStatus(0), protocol.ReplyStatus(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.To5(); got != tt.expected {
				t.Errorf("ReplyStatus.To5() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestReplyStatus_To4(t *testing.T) {
	tests := []struct {
		name     string
		status   protocol.ReplyStatus
		expected protocol.ReplyStatus
	}{
		// SOCKS5 conversions
		{"SuccReply to Granted", protocol.SuccReply, protocol.Granted},
		{"FailReply to Rejected", protocol.FailReply, protocol.Rejected},
		{
			"DisallowReply to Rejected",
			protocol.DisallowReply,
			protocol.Rejected,
		},
		{
			"NetUnreachReply to Rejected",
			protocol.NetUnreachReply,
			protocol.Rejected,
		},
		{
			"HostUnreachReply to Rejected",
			protocol.HostUnreachReply,
			protocol.Rejected,
		},
		{
			"ConnRefusedReply to Rejected",
			protocol.ConnRefusedReply,
			protocol.Rejected,
		},
		{
			"TTLExpiredReply to Rejected",
			protocol.TTLExpiredReply,
			protocol.Rejected,
		},
		{
			"CmdNotSuppReply to Rejected",
			protocol.CmdNotSuppReply,
			protocol.Rejected,
		},
		{
			"AddrNotSuppReply to Rejected",
			protocol.AddrNotSuppReply,
			protocol.Rejected,
		},

		// Tor conversions (all to Rejected)
		{
			"TorDescNotFound to Rejected",
			protocol.TorDescNotFound,
			protocol.Rejected,
		},
		{
			"TorDescInvalid to Rejected",
			protocol.TorDescInvalid,
			protocol.Rejected,
		},
		{"TorIntroFail to Rejected", protocol.TorIntroFail, protocol.Rejected},
		{
			"TorRendFailed to Rejected",
			protocol.TorRendFailed,
			protocol.Rejected,
		},
		{"TorMissAuth to Rejected", protocol.TorMissAuth, protocol.Rejected},
		{"TorWrongAuth to Rejected", protocol.TorWrongAuth, protocol.Rejected},
		{
			"TorInvalidAddr to Rejected",
			protocol.TorInvalidAddr,
			protocol.Rejected,
		},
		{
			"TorIntroTimeOut to Rejected",
			protocol.TorIntroTimeOut,
			protocol.Rejected,
		},

		// SOCKS4 should stay the same
		{"Granted stays", protocol.Granted, protocol.Granted},
		{"Rejected stays", protocol.Rejected, protocol.Rejected},
		{"IdentRequired stays", protocol.IdentRequired, protocol.IdentRequired},
		{"IdentFailed stays", protocol.IdentFailed, protocol.IdentFailed},

		// Unknown values
		{
			"Unknown stays",
			protocol.ReplyStatus(0xfa),
			protocol.ReplyStatus(0xfa),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.To4(); got != tt.expected {
				t.Errorf("ReplyStatus.To4() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Test all constants are defined
func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant protocol.ReplyStatus
		value    uint8
	}{
		{"SuccReply", protocol.SuccReply, 0x0},
		{"FailReply", protocol.FailReply, 0x1},
		{"DisallowReply", protocol.DisallowReply, 0x2},
		{"NetUnreachReply", protocol.NetUnreachReply, 0x3},
		{"HostUnreachReply", protocol.HostUnreachReply, 0x4},
		{"ConnRefusedReply", protocol.ConnRefusedReply, 0x5},
		{"TTLExpiredReply", protocol.TTLExpiredReply, 0x6},
		{"CmdNotSuppReply", protocol.CmdNotSuppReply, 0x7},
		{"AddrNotSuppReply", protocol.AddrNotSuppReply, 0x80},

		{"Granted", protocol.Granted, 90},
		{"Rejected", protocol.Rejected, 91},
		{"IdentRequired", protocol.IdentRequired, 92},
		{"IdentFailed", protocol.IdentFailed, 93},

		{"TorDescNotFound", protocol.TorDescNotFound, 0xf0},
		{"TorDescInvalid", protocol.TorDescInvalid, 0xf1},
		{"TorIntroFail", protocol.TorIntroFail, 0xf2},
		{"TorRendFailed", protocol.TorRendFailed, 0xf3},
		{"TorMissAuth", protocol.TorMissAuth, 0xf4},
		{"TorWrongAuth", protocol.TorWrongAuth, 0xf5},
		{"TorInvalidAddr", protocol.TorInvalidAddr, 0xf6},
		{"TorIntroTimeOut", protocol.TorIntroTimeOut, 0xf7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uint8(tt.constant) != tt.value {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.value)
			}
		})
	}
}
