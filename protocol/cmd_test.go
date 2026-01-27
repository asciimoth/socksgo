package protocol_test

import (
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

func TestCmdString(t *testing.T) {
	tests := []struct {
		name     string
		cmd      protocol.Cmd
		expected string
	}{
		// Test all defined commands
		{
			name:     "CmdConnect",
			cmd:      protocol.CmdConnect,
			expected: "cmd connect",
		},
		{
			name:     "CmdBind",
			cmd:      protocol.CmdBind,
			expected: "cmd bind",
		},
		{
			name:     "CmdUDPAssoc",
			cmd:      protocol.CmdUDPAssoc,
			expected: "cmd UDP associate",
		},
		{
			name:     "CmdTorResolve",
			cmd:      protocol.CmdTorResolve,
			expected: "cmd tor resolve",
		},
		{
			name:     "CmdTorResolvePtr",
			cmd:      protocol.CmdTorResolvePtr,
			expected: "cmd tor resolve_ptr",
		},
		{
			name:     "CmdGostMuxBind",
			cmd:      protocol.CmdGostMuxBind,
			expected: "cmd gost mbind",
		},
		{
			name:     "CmdGostUDPTun",
			cmd:      protocol.CmdGostUDPTun,
			expected: "cmd gost udp tun",
		},

		// Test edge cases and unknown commands
		{
			name:     "zero value",
			cmd:      protocol.Cmd(0x00),
			expected: "cmd no0",
		},
		{
			name:     "unknown command 0x04",
			cmd:      protocol.Cmd(0x04),
			expected: "cmd no4",
		},
		{
			name:     "unknown command 0xFF",
			cmd:      protocol.Cmd(0xFF),
			expected: "cmd no255",
		},
		{
			name:     "unknown command 0x7F",
			cmd:      protocol.Cmd(0x7F),
			expected: "cmd no127",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cmd.String()
			if result != tt.expected {
				t.Errorf(
					"Cmd(%#x).String() = %q, want %q",
					tt.cmd,
					result,
					tt.expected,
				)
			}
		})
	}
}

func TestCmdConstants(t *testing.T) {
	// Verify all constants have the correct values
	constantTests := []struct {
		name     string
		cmd      protocol.Cmd
		expected protocol.Cmd
	}{
		{"CmdConnect", protocol.CmdConnect, 0x01},
		{"CmdBind", protocol.CmdBind, 0x02},
		{"CmdUDPAssoc", protocol.CmdUDPAssoc, 0x03},
		{"CmdTorResolve", protocol.CmdTorResolve, 0xF0},
		{"CmdTorResolvePtr", protocol.CmdTorResolvePtr, 0xF1},
		{"CmdGostMuxBind", protocol.CmdGostMuxBind, 0xF2},
		{"CmdGostUDPTun", protocol.CmdGostUDPTun, 0xF3},
	}

	for _, tt := range constantTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cmd != tt.expected {
				t.Errorf("%s = %#x, want %#x", tt.name, tt.cmd, tt.expected)
			}
		})
	}
}
