package protocol

import "strconv"

const (
	CmdConnect       Cmd = 0x01
	CmdBind          Cmd = 0x02
	CmdUDPAssoc      Cmd = 0x03
	CmdTorResolve    Cmd = 0xF0
	CmdTorResolvePtr Cmd = 0xF1
	CmdGostMuxBind   Cmd = 0xF2
	CmdGostUDPTun    Cmd = 0xF3
)

type Cmd uint8

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
