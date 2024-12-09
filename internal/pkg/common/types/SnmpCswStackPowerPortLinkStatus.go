package types

import "fmt"

type SnmpCswStackPowerPortLinkStatus uint8

const (
	SnmpCswStackPowerPortLinkStatusUp SnmpCswStackPowerPortLinkStatus = iota + 1
	SnmpCswStackPowerPortLinkStatusDown
)

func (c SnmpCswStackPowerPortLinkStatus) String() string {
	switch c {
	case SnmpCswStackPowerPortLinkStatusUp:
		return "SnmpCswStackPortOperStateUp"
	case SnmpCswStackPowerPortLinkStatusDown:
		return "SnmpCswStackPortOperStateDown"
	default:
		return fmt.Sprintf("UnknownClass(%d)", c)
	}
}
