package types

import "fmt"

type SnmpCiscoEnvMonState uint8

const (
	CiscoEnvMonStateNormal SnmpCiscoEnvMonState = iota + 1
	CiscoEnvMonStateWarning
	CiscoEnvMonStateCritical
	CiscoEnvMonStateShutdown
	CiscoEnvMonStateNotPresent
	CiscoEnvMonStateNotFunctioning
)

func (c SnmpCiscoEnvMonState) String() string {
	switch c {
	case CiscoEnvMonStateNormal:
		return "CiscoEnvMonStateNormal"
	case CiscoEnvMonStateWarning:
		return "CiscoEnvMonStateWarning"
	case CiscoEnvMonStateCritical:
		return "CiscoEnvMonStateCritical"
	case CiscoEnvMonStateShutdown:
		return "CiscoEnvMonStateShutdown"
	case CiscoEnvMonStateNotPresent:
		return "CiscoEnvMonStateNotPresent"
	case CiscoEnvMonStateNotFunctioning:
		return "CiscoEnvMonStateNotFunctioning"
	default:
		return fmt.Sprintf("UnknownClass(%d)", c)
	}
}
