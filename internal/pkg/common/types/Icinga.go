package types

import "fmt"

type IcingaStatusVal uint8

const (
	IcingaOK IcingaStatusVal = iota
	IcingaWARN
	IcingaCRITICAL
	IcingaUNKNOWN
)

func (c IcingaStatusVal) String() string {
	switch c {
	case IcingaOK:
		return "OK"
	case IcingaWARN:
		return "WARN"
	case IcingaCRITICAL:
		return "CRITICAL"
	case IcingaUNKNOWN:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("UnknownClass(%d)", c)
	}
}

type IcingaStatus struct {
	Message  string
	PerfData string
	Value    IcingaStatusVal
}
