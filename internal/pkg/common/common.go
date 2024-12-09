package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	g "github.com/gosnmp/gosnmp"

	. "github.com/jamiereid/go-icingaplugins/internal/pkg/common/types"
)

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
		return fmt.Errorf("SNMP Error: %v\n", pdu.Error)
	}

	return nil
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
