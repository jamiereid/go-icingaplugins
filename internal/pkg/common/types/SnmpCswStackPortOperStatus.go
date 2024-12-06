package types

import "fmt"

type SnmpCswStackPortOperStatus uint8

const (
	SnmpCswStackPortOperStatusUp SnmpCswStackPortOperStatus = iota + 1
	SnmpCswStackPortOperStatusDown
	SnmpCswStackPortOperStatusForcedDown
)

func (c SnmpCswStackPortOperStatus) String() string {
	switch c {
	case SnmpCswStackPortOperStatusUp:
		return "SnmpCswStackPortOperStateUp"
	case SnmpCswStackPortOperStatusDown:
		return "SnmpCswStackPortOperStateDown"
	case SnmpCswStackPortOperStatusForcedDown:
		return "SnmpCswStackPortOperStateForcedDown"
	default:
		return fmt.Sprintf("UnknownClass(%d)", c)
	}
}
