package types

import "fmt"

type SnmpIfOperStatus uint8

const (
	IfOperStatusUp SnmpIfOperStatus = iota + 1
	IfOperStatusDown
	IfOperStatusTesting
	IfOperStatusUnknown
	IfOperStatusDormant
	IfOperStatusNotPresent
	IfOperStatusLowerLayerDown
)

func (c SnmpIfOperStatus) String() string {
	switch c {
	case IfOperStatusUp:
		return "IfOperStatusUp"
	case IfOperStatusDown:
		return "IfOperStatusDown"
	case IfOperStatusTesting:
		return "IfOperStatusTesting"
	case IfOperStatusUnknown:
		return "IfOperStatusUnknown"
	case IfOperStatusDormant:
		return "IfOperStatusDormant"
	case IfOperStatusNotPresent:
		return "IfOperStatusNotPresent"
	case IfOperStatusLowerLayerDown:
		return "IfOperStatusLowerLayerDown"
	default:
		return fmt.Sprintf("UnknownIfOperStatus(%d)", c)
	}
}
