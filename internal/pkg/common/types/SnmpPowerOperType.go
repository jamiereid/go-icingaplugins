package types

import "fmt"

type SnmpPowerOperType uint8

const (
	PowerOperTypeOffEnvOther SnmpPowerOperType = iota + 1
	PowerOperTypeOn
	PowerOperTypeOffAdmin
	PowerOperTypeOffDenied
	PowerOperTypeOffEnvPower
	PowerOperTypeOffEnvTemp
	PowerOperTypeOffEnvFan
	PowerOperTypeFailed
	PowerOperTypeOnButFanFail
	PowerOperTypeOffCooling
	PowerOperTypeOffConnectorRating
	PowerOperTypeOnButInlinePowerFail
)

func (c SnmpPowerOperType) String() string {
	switch c {
	case PowerOperTypeOffEnvOther:
		return "PowerOperTypeOffEnvOther"
	case PowerOperTypeOn:
		return "PowerOperTypeOn"
	case PowerOperTypeOffAdmin:
		return "PowerOperTypeOffAdmin"
	case PowerOperTypeOffDenied:
		return "PowerOperTypeOffDenied"
	case PowerOperTypeOffEnvPower:
		return "PowerOperTypeOffEnvPower"
	case PowerOperTypeOffEnvTemp:
		return "PowerOperTypeOffEnvTemp"
	case PowerOperTypeOffEnvFan:
		return "PowerOperTypeOffEnvFan"
	case PowerOperTypeFailed:
		return "PowerOperTypeFailed"
	case PowerOperTypeOnButFanFail:
		return "PowerOperTypeOnButFanFail"
	case PowerOperTypeOffCooling:
		return "PowerOperTypeOffCooling"
	case PowerOperTypeOffConnectorRating:
		return "PowerOperTypeOffConnectorRating"
	case PowerOperTypeOnButInlinePowerFail:
		return "PowerOperTypeOnButInlinePowerFail"
	default:
		return fmt.Sprintf("UnknownClass(%d)", c)
	}
}
