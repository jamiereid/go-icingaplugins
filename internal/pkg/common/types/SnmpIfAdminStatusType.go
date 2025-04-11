package types

import "fmt"

type SnmpIfAdminStatus uint8

const (
	IfAdminStatusUp SnmpIfAdminStatus = iota + 1
	IfAdminStatusDown
	IfAdminStatusTesting
)

func (c SnmpIfAdminStatus) String() string {
	switch c {
	case IfAdminStatusUp:
		return "IfAdminStatusUp"
	case IfAdminStatusDown:
		return "IfAdminStatusDown"
	case IfAdminStatusTesting:
		return "IfAdminStatusTesting"
	default:
		return fmt.Sprintf("UnknownIfAdminStatus(%d)", c)
	}
}
