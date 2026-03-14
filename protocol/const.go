// Package protocol implements low-level SOCKS protocol encoding and decoding.
//
// This package provides the building blocks for SOCKS4, SOCKS4a, and SOCKS5
// protocols, including address representation, command codes, reply status
// codes, authentication negotiation, and wire format encoding/decoding.
//
// # Protocol References
//
//   - RFC 1928: SOCKS Protocol Version 5
//   - RFC 1929: Username/Password Authentication for SOCKS V5
//   - SOCKS4/SOCKS4a: https://www.openssh.com/txt/socks4.protocol
//   - Tor SOCKS Extensions: https://spec.torproject.org/socks-extensions.html
package protocol

// Protocol constants for buffer sizes and limits.
//
// These constants define maximum sizes for various SOCKS protocol elements
// and are used for buffer allocation throughout the library.
const (
	// MAX_HEADER_STR_LENGTH is the maximum length for string fields in the
	// SOCKS protocol (e.g., FQDN in address, username in auth).
	// This is a hard limit.
	MAX_HEADER_STR_LENGTH = 255

	// MAX_SOCKS_TCP_HEADER_LEN is the maximum size of a SOCKS TCP request
	// or reply header. Calculated as:
	//   - 3 bytes: version + command/reserved + address type
	//   - 1 byte: FQDN length (if applicable)
	//   - 255 bytes: maximum FQDN length
	//   - 2 bytes: port
	// Total: 7 + 255 = 262 bytes
	MAX_SOCKS_TCP_HEADER_LEN = 7 + MAX_HEADER_STR_LENGTH

	// MAX_SOCKS_UDP_HEADER_LEN is the maximum size of a SOCKS5 UDP packet
	// header. Has the same structure as TCP header:
	//   - 2 bytes: RSV (reserved/fragment)
	//   - 1 byte: FRAG (fragment flag)
	//   - 1 byte: address type
	//   - 1 byte: FQDN length (if applicable)
	//   - 255 bytes: maximum FQDN length
	//   - 2 bytes: port
	// Total: 7 + 255 = 262 bytes
	MAX_SOCKS_UDP_HEADER_LEN = 7 + MAX_HEADER_STR_LENGTH

	// GOST_UDP_FRAG_FLAG is the fragment value used in Gost's UDP Tunnel
	// extension to indicate a complete (non-fragmented) packet.
	// Standard SOCKS5 uses 0x00 for no fragmentation.
	// Gost uses 0xFF (255) to identify its UDP tunnel format.
	GOST_UDP_FRAG_FLAG = 255

	// MAX_AUTH_METHODS_COUNT is the maximum number of authentication methods
	// a client can advertise in the SOCKS5 authentication negotiation.
	// The SOCKS5 protocol uses a single byte for the count, limiting it to
	// 255 methods (0 is reserved, so 255 is the practical maximum).
	MAX_AUTH_METHODS_COUNT = 255
)
