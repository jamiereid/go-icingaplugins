package types

import "fmt"

type SnmpIanaPhysicalClass uint8

const (
	IanaPhysicalClassOther SnmpIanaPhysicalClass = iota + 1
	IanaPhysicalClassUnknown
	IanaPhysicalClassChassis
	IanaPhysicalClassBackPlane
	IanaPhysicalClassContainer
	IanaPhysicalClassPowerSupply
	IanaPhysicalClassFan
	IanaPhysicalClassSensor
	IanaPhysicalClassModule
	IanaPhysicalClassPort
	IanaPhysicalClassStack
	IanaPhysicalClassCPU
)

func (c SnmpIanaPhysicalClass) String() string {
	switch c {
	case IanaPhysicalClassOther:
		return "IanaPhysicalClassOther"
	case IanaPhysicalClassUnknown:
		return "IanaPhysicalClassUnknown"
	case IanaPhysicalClassChassis:
		return "IanaPhysicalClassChassis"
	case IanaPhysicalClassBackPlane:
		return "IanaPhysicalClassBackPlane"
	case IanaPhysicalClassContainer:
		return "IanaPhysicalClassContainer"
	case IanaPhysicalClassPowerSupply:
		return "IanaPhysicalClassPowerSupply"
	case IanaPhysicalClassFan:
		return "IanaPhysicalClassFan"
	case IanaPhysicalClassSensor:
		return "IanaPhysicalClassSensor"
	case IanaPhysicalClassModule:
		return "IanaPhysicalClassModule"
	case IanaPhysicalClassPort:
		return "IanaPhysicalClassPort"
	case IanaPhysicalClassStack:
		return "IanaPhysicalClassStack"
	case IanaPhysicalClassCPU:
		return "IanaPhysicalClassCPU"
	default:
		return fmt.Sprintf("UnknownClass(%d)", c)
	}
}
