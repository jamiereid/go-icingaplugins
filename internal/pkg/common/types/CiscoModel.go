package types

type CiscoModelFamily uint8

const (
	CiscoModelFamilyUnknown CiscoModelFamily = iota
	CiscoModelFamilyISR
	CiscoModelFamily9500
	CiscoModelFamily9300X
	CiscoModelFamily9300
	CiscoModelFamily9200
	CiscoModelFamily6800
	CiscoModelFamily4500X
	CiscoModelFamily4500
	CiscoModelFamily3850
	CiscoModelFamily3800
	CiscoModelFamily3750X
	CiscoModelFamily3750
	CiscoModelFamily3560
	CiscoModelFamily2960X
	CiscoModelFamily2960
)

func NewCiscoModelFamily(input string) CiscoModelFamily {
	switch input {
	case "IR1101":
		return CiscoModelFamilyISR
	case "9500", "C9500":
		return CiscoModelFamily9500
	case "9300X", "C9300X":
		return CiscoModelFamily9300X
	case "9300", "C9300", "9300LM", "C9300LM":
		return CiscoModelFamily9300
	case "9200", "C9200", "9200CX", "C9200CX":
		return CiscoModelFamily9200
	case "6816", "C6816", "6880", "C6880":
		return CiscoModelFamily6800
	case "4500X", "C4500X":
		return CiscoModelFamily4500X
	case "4510", "C4510":
		return CiscoModelFamily4500
	case "3850", "C3850":
		return CiscoModelFamily3850
	case "3800", "C3800", "3800X":
		return CiscoModelFamily3800
	case "3750X", "C3750X":
		return CiscoModelFamily3750X
	case "3750", "C3750":
		return CiscoModelFamily3750
	case "3560", "C3560", "3560CG", "C3560CG", "3560CX", "C3560CX":
		return CiscoModelFamily3560
	case "2960X", "C2960X":
		return CiscoModelFamily2960X
	case "2960", "C2960", "2960S", "C2960S":
		return CiscoModelFamily2960
	default:
		return CiscoModelFamilyUnknown
	}
}

func (c CiscoModelFamily) String() string {
	switch c {
	case CiscoModelFamilyISR:
		return "Cisco ISR Family"
	case CiscoModelFamily9500:
		return "Cisco 9500 Family"
	case CiscoModelFamily9300X:
		return "Cisco 9300X Family"
	case CiscoModelFamily9300:
		return "Cisco 9300 Family"
	case CiscoModelFamily9200:
		return "Cisco 9200 Family"
	case CiscoModelFamily6800:
		return "Cisco 6800 Family"
	case CiscoModelFamily4500X:
		return "Cisco 4500X Family"
	case CiscoModelFamily4500:
		return "Cisco 4500 Family"
	case CiscoModelFamily3850:
		return "Cisco 3850 Family"
	case CiscoModelFamily3800:
		return "Cisco 3800 Family"
	case CiscoModelFamily3750X:
		return "Cisco 3750X Family"
	case CiscoModelFamily3750:
		return "Cisco 3750 Family"
	case CiscoModelFamily3560:
		return "Cisco 3560 Family"
	case CiscoModelFamily2960X:
		return "Cisco 2960X Family"
	case CiscoModelFamily2960:
		return "Cisco 2960 Family"
	default:
		return "Model family not recognized"
	}
}
