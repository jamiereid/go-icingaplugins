package types

import "fmt"

type SnmpCswSwitchState uint8

const (
	SnmpCswSwitchStateWaiting SnmpCswSwitchState = iota + 1
	SnmpCswSwitchStateProgressing
	SnmpCswSwitchStateAdded
	SnmpCswSwitchStateReady
	SnmpCswSwitchStateSdmMismatch
	SnmpCswSwitchStateVerMismatch
	SnmpCswSwitchStateFeatureMismatch
	SnmpCswSwitchStateNewMasterInit
	SnmpCswSwitchStateProvisioned
	SnmpCswSwitchStateInvalid
	SnmpCswSwitchStateRemoved
)

func (c SnmpCswSwitchState) String() string {
	switch c {
	case SnmpCswSwitchStateWaiting:
		return "SnmpCswSwitchStateWaiting"
	case SnmpCswSwitchStateProgressing:
		return "SnmpCswSwitchStateProgressing"
	case SnmpCswSwitchStateAdded:
		return "SnmpCswSwitchStateAdded"
	case SnmpCswSwitchStateReady:
		return "SnmpCswSwitchStateReady"
	case SnmpCswSwitchStateSdmMismatch:
		return "SnmpCswSwitchStateSdmMismatch"
	case SnmpCswSwitchStateVerMismatch:
		return "SnmpCswSwitchStateVerMismatch"
	case SnmpCswSwitchStateFeatureMismatch:
		return "SnmpCswSwitchStateFeatureMismatch"
	case SnmpCswSwitchStateNewMasterInit:
		return "SnmpCswSwitchStateNewMasterInit"
	case SnmpCswSwitchStateProvisioned:
		return "SnmpCswSwitchStateProvisioned"
	case SnmpCswSwitchStateInvalid:
		return "SnmpCswSwitchStateInvalid"
	case SnmpCswSwitchStateRemoved:
		return "SnmpCswSwitchStateRemoved"
	default:
		return fmt.Sprintf("UnknownClass(%d)", c)
	}
}
