package common

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	g "github.com/gosnmp/gosnmp"

	. "github.com/jamiereid/go-icingaplugins/internal/pkg/common/types"
)

const LevelTrace = slog.Level(-6)

func BulkWalkToStringMap(conn *g.GoSNMP, oid string) (map[string]interface{}, error) {
	var returnMap = make(map[string]interface{})

	// @TODO: Check for start and end in "." - only concat if we need to
	prefixBytes := []byte("." + oid + ".")
	err := conn.BulkWalk(oid, func(pdu g.SnmpPDU) error {
		if pdu.Value == nil {
			return fmt.Errorf("recieved a PDU with a nil value")
		}

		nameBytes := []byte(pdu.Name)
		if len(nameBytes) <= len(prefixBytes) || string(nameBytes[:len(prefixBytes)]) != string(prefixBytes) {
			return fmt.Errorf("unexpected OID format: %s", pdu.Name)
		}

		keyPart := nameBytes[len(prefixBytes):]
		key := string(keyPart)

		switch pdu.Type {
		case g.OctetString:
			returnMap[key] = string(pdu.Value.([]byte))
		case g.Integer:
			returnMap[key] = pdu.Value.(int)
		case g.Counter32, g.Gauge32, g.TimeTicks:
			returnMap[key] = uint32(pdu.Value.(uint))
		case g.Counter64:
			returnMap[key] = pdu.Value.(uint64)
		default:
			return fmt.Errorf("unsupported SNMP type: %v", pdu.Type)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error during BulkWalk: %w", err)
	}

	return returnMap, nil

}

func BulkWalkToMap(conn *g.GoSNMP, oid string) (map[int]interface{}, error) {
	var returnMap = make(map[int]interface{})

	// @TODO: Check for start and end in "." - only concat if we need to
	prefixBytes := []byte("." + oid + ".")
	err := conn.BulkWalk(oid, func(pdu g.SnmpPDU) error {
		if pdu.Value == nil {
			return fmt.Errorf("recieved a PDU with a nil value")
		}

		nameBytes := []byte(pdu.Name)
		if len(nameBytes) <= len(prefixBytes) || string(nameBytes[:len(prefixBytes)]) != string(prefixBytes) {
			return fmt.Errorf("unexpected OID format: %s", pdu.Name)
		}

		keyPart := nameBytes[len(prefixBytes):]
		key, err := strconv.Atoi(string(keyPart))
		if err != nil {
			return fmt.Errorf("failed to cast index to int: %w", err)
		}

		switch pdu.Type {
		case g.OctetString:
			returnMap[key] = string(pdu.Value.([]byte))
		case g.Integer:
			returnMap[key] = pdu.Value.(int)
		case g.Counter32, g.Gauge32, g.TimeTicks:
			returnMap[key] = uint32(pdu.Value.(uint))
		case g.Counter64:
			returnMap[key] = pdu.Value.(uint64)
		default:
			return fmt.Errorf("unsupported SNMP type: %v", pdu.Type)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error during BulkWalk: %w", err)
	}

	return returnMap, nil

}

func ExitPlugin(status *IcingaStatus) {
	var exitMsg strings.Builder

	exitMsg.WriteString(status.Value.String())
	exitMsg.WriteString(": ")
	exitMsg.WriteString(status.Message)

	if status.PerfData != "" {
		exitMsg.WriteString(" | ")
		exitMsg.WriteString(status.PerfData)
	}

	fmt.Fprintln(os.Stdout, exitMsg.String())
	os.Exit(int(status.Value))
}

func CheckConnection(params *g.GoSNMP) error {

	err := params.Connect()
	if err != nil {
		return fmt.Errorf("Error when connecting: %w", err)
	}
	defer params.Conn.Close()

	pdu, err := params.Get([]string{"1.3.6.1.2.1.1.5.0"}) // sysName
	if err != nil {
		return fmt.Errorf("Error when attempting to get sysName: %w", err)
	}

	if pdu.Error != g.NoError {
		return fmt.Errorf("SNMP Error: %v\n", pdu.Error.String())
	}

	return nil
}

func GetDeviceModel(params *g.GoSNMP) (*CiscoModelFamily, string, error) {

	err := params.Connect()
	if err != nil {
		return nil, "", fmt.Errorf("Error when connecting: %w", err)
	}
	defer params.Conn.Close()

	// get entPhysicalClass
	result, err := BulkWalkToMap(params, "1.3.6.1.2.1.47.1.1.1.1.5")
	if err != nil {
		return nil, "", fmt.Errorf("Error: %v\n", err)
	}
	entPhysicalClass := make(map[int]SnmpIanaPhysicalClass)
	for it_index, it := range result {
		v, ok := it.(int)
		if !ok {
			fmt.Printf("Value for key %d is not an int: %v\n", it_index, it)
			continue
		}
		entPhysicalClass[it_index] = SnmpIanaPhysicalClass(v)
	}

	// If we can take an early out and avoid looping over the entPhysicalClass slice to find a
	// chassis, then do so - otherwise, we are either checking a stack (IanaPhysicalClassStack)
	// or we are checking agaist a model that doesn't index from 1.
	var entIndex = 1
	if entPhysicalClass[1] != IanaPhysicalClassChassis {
		//
		// in our environment, it's ok to assume that all stack chassis are in the
		// same device family - this might not be true in all environments
		// (eg. 9300 and 9300X) and something smarter might need to be done here.
		//                                             - jreid, 18 Dec 2024
		//
		for it_index, it := range entPhysicalClass {
			if it == IanaPhysicalClassChassis {
				entIndex = it_index
				break
			}
		}
	}

	pdu, err := params.Get([]string{fmt.Sprintf("1.3.6.1.2.1.47.1.1.1.1.13.%v", entIndex)}) // entPhysicalModelName
	if err != nil {
		return nil, "", fmt.Errorf("Error when attempting to get entPhysicalModelName.%v: %w", entIndex, err)
	}

	if pdu.Error != g.NoError {
		return nil, "", fmt.Errorf("SNMP Error: %v\n", pdu.Error.String())
	}

	if pdu.Variables[0].Type == g.NoSuchInstance {
		return nil, "", fmt.Errorf("SNMP Response: No Such Instance\n")
	}

	// this can probably be deleted once we know the changes above are ok. @Cleanup
	// our assumption of entPhysicalClass[1] was invalid. We might want to @Refactor this into the above
	// to avoid a second for loop...
	//                                                           - jreid, 23 December 2024
	// if pdu.Variables[0].Type == g.NoSuchInstance {
	// 	for it_index, it := range entPhysicalClass {
	// 		if it == IanaPhysicalClassChassis {
	// 			entIndex = it_index
	// 			break
	// 		}
	// 	}
	//
	// 	pdu, err = params.Get([]string{fmt.Sprintf("1.3.6.1.2.1.47.1.1.1.1.13.%v", entIndex)}) // entPhysicalModelName
	// 	if err != nil {
	// 		return nil, "", fmt.Errorf("Error when attempting to get entPhysicalModelName.%v: %w", entIndex, err)
	// 	}
	// }
	//
	deviceModelAsString := string(pdu.Variables[0].Value.([]byte))

	// @Speed
	if strings.HasPrefix(deviceModelAsString, "WS-") {
		deviceModelAsString = strings.TrimPrefix(deviceModelAsString, "WS-")
	}
	if strings.HasPrefix(deviceModelAsString, "ME-") {
		deviceModelAsString = strings.TrimPrefix(deviceModelAsString, "ME-")
	}
	if strings.HasSuffix(deviceModelAsString, "R+E") { // 4510 @Hack
		deviceModelAsString = strings.TrimSuffix(deviceModelAsString, "R+E")
	}

	familyPart, _, _ := strings.Cut(deviceModelAsString, "-") // @Assumption: success
	returnValue := NewCiscoModelFamily(familyPart)
	return &returnValue, deviceModelAsString, nil
}

// Get indexes of IanaPhysicalClassChassis
func GetStackMembers(params *g.GoSNMP) ([]int, error) {

	err := params.Connect()
	if err != nil {
		return nil, fmt.Errorf("Error when connecting: %w", err)
	}
	defer params.Conn.Close()

	// get entPhysicalClass
	result, err := BulkWalkToMap(params, "1.3.6.1.2.1.47.1.1.1.1.5")
	if err != nil {
		return nil, fmt.Errorf("BulkWalk of device (%v) failed: %w\n", params.Target, err)
	}
	entPhysicalClass := make(map[int]SnmpIanaPhysicalClass)
	for it_index, it := range result {
		v, ok := it.(int)
		if !ok {
			slog.Warn("Unable to convert value to int", "oid", "1.3.6.1.2.1.47.1.1.1.1.5", "key", it_index, "raw_value", it)
			continue
		}
		entPhysicalClass[it_index] = SnmpIanaPhysicalClass(v)
	}

	var returnSlice []int
	if entPhysicalClass[1] == IanaPhysicalClassStack {
		for it_index, it := range entPhysicalClass {
			if it == IanaPhysicalClassChassis {
				returnSlice = append(returnSlice, it_index)
			}
		}
	} else {
		returnSlice = append(returnSlice, 1)
	}

	return returnSlice, nil
}

func DebugPrint(pdu g.SnmpPDU) {
	switch pdu.Type {
	case g.OctetString:
		b := pdu.Value.([]byte)
		fmt.Printf("STRING: %s\n", string(b))
	default:
		fmt.Printf("TYPE %v: %d\n", g.Asn1BER(pdu.Type), g.ToBigInt(pdu.Value))
	}
}

// SetupLogging configures the slog logger based on the verbosity level
func SetupLogging(verbosity int) {
	var level slog.Level

	var levelNames = map[slog.Leveler]string{
		LevelTrace: "TRACE",
	}

	switch verbosity {
	case 0:
		level = slog.LevelWarn // Default: show warnings and higher
	case 1:
		level = slog.LevelInfo // -v: show info and higher
	case 2:
		level = slog.LevelDebug // -vv: show debug and higher
	default:
		level = slog.LevelDebug - slog.Level(verbosity-2) // Beyond -vv: Trace-like levels
	}

	// Clamp level to a reasonable range (e.g., Trace or custom verbose levels)
	if level < slog.Level(-10) {
		level = slog.Level(-10) // Minimum level
	}

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				level := a.Value.Any().(slog.Level)
				levelLabel, exists := levelNames[level]
				if !exists {
					levelLabel = level.String()
				}

				a.Value = slog.StringValue(levelLabel)
			}

			return a
		},
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}
