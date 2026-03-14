package protocol

import "strconv"

// SOCKS command codes.
//
// These constants define the command values used in SOCKS requests.
// Standard commands (Connect, Bind, UDPAssoc) are defined in RFC 1928.
// Extension commands (TorResolve, TorResolvePtr, GostMuxBind, GostUDPTun)
// are defined by their respective projects.
const (
	// CmdConnect establishes a TCP connection to the target address.
	// Standard SOCKS command (RFC 1928).
	// Wire value: 0x01
	CmdConnect Cmd = 0x01

	// CmdBind listens for incoming connections on the server.
	// Standard SOCKS command (RFC 1928).
	// Used for protocols that require reverse connections (e.g., FTP passive mode).
	// Wire value: 0x02
	CmdBind Cmd = 0x02

	// CmdUDPAssoc associates a UDP port for UDP relay.
	// Standard SOCKS command (RFC 1928).
	// Returns a UDP socket address for sending/receiving UDP packets.
	// Wire value: 0x03
	CmdUDPAssoc Cmd = 0x03

	// CmdTorResolve performs a forward DNS lookup (Tor extension).
	// https://spec.torproject.org/socks-extensions.html
	// Wire value: 0xF0
	CmdTorResolve Cmd = 0xF0

	// CmdTorResolvePtr performs a reverse DNS lookup (Tor extension).
	// https://spec.torproject.org/socks-extensions.html
	// Wire value: 0xF1
	CmdTorResolvePtr Cmd = 0xF1

	// CmdGostMuxBind creates a multiplexed bind using smux (Gost extension).
	// Allows multiple incoming connections over a single TCP connection.
	// Wire value: 0xF2
	CmdGostMuxBind Cmd = 0xF2

	// CmdGostUDPTun tunnels UDP over TCP (Gost extension).
	// Encapsulates UDP packets in a TCP connection.
	// Wire value: 0xF3
	CmdGostUDPTun Cmd = 0xF3
)

// Cmd represents a SOCKS command code.
//
// Cmd is used in SOCKS requests to specify the operation the client wants
// the server to perform. Standard commands are defined in RFC 1928,
// while extension commands are defined by Tor and Gost projects.
//
// # Examples
//
//	// Check command type
//	if cmd == protocol.CmdConnect {
//	    // Handle CONNECT command
//	}
//
//	// String representation
//	cmd.String() // Returns "cmd connect"
type Cmd uint8

// String returns a human-readable description of the command.
//
// Returns descriptive strings for known commands:
//   - "cmd connect" for CmdConnect
//   - "cmd bind" for CmdBind
//   - "cmd UDP associate" for CmdUDPAssoc
//   - "cmd tor resolve" for CmdTorResolve
//   - "cmd tor resolve_ptr" for CmdTorResolvePtr
//   - "cmd gost mbind" for CmdGostMuxBind
//   - "cmd gost udp tun" for CmdGostUDPTun
//
// For unknown command values, returns "cmd noX" where X is the numeric value.
func (cmd Cmd) String() string {
	switch cmd {
	case CmdConnect:
		return "cmd connect"
	case CmdBind:
		return "cmd bind"
	case CmdUDPAssoc:
		return "cmd UDP associate"
	case CmdTorResolve:
		return "cmd tor resolve"
	case CmdTorResolvePtr:
		return "cmd tor resolve_ptr"
	case CmdGostMuxBind:
		return "cmd gost mbind"
	case CmdGostUDPTun:
		return "cmd gost udp tun"
	default:
		return "cmd no" + strconv.Itoa(int(cmd))
	}
}
