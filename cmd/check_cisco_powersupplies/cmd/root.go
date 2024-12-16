package cmd

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/jamiereid/go-icingaplugins/internal/pkg/common"
	. "github.com/jamiereid/go-icingaplugins/internal/pkg/common/types"

	"github.com/spf13/cobra"

	g "github.com/gosnmp/gosnmp"
)

var Debug bool
var conn g.GoSNMP
var secparams g.UsmSecurityParameters
var timeout int
var seclevel SnmpV3MsgFlagsValue
var authmode SnmpV3AuthProtocolValue
var privmode SnmpV3PrivProtocolValue
var doubleContainers bool
var psuBuiltIn bool
var psuExpectedOverrideValue uint8

const entPhysicalDescrOID string = "1.3.6.1.2.1.47.1.1.1.1.2"
const entPhysicalClassOID string = "1.3.6.1.2.1.47.1.1.1.1.5"
const ciscoEnvMonSupplyStateOID string = "1.3.6.1.4.1.9.9.13.1.5.1.3"
const cefcFruPowerOperStatusOID string = "1.3.6.1.4.1.9.9.117.1.1.2.1.2"

var rootCmd = &cobra.Command{
	Use:   "check_cisco_powersupplies",
	Short: "Cisco power supplies module check plugin",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		conn.Version = g.Version3
		conn.SecurityModel = g.UserSecurityModel
		conn.MsgFlags = seclevel.Value
		conn.Timeout = time.Duration(timeout) * time.Second

		secparams.AuthenticationProtocol = authmode.Value
		secparams.PrivacyProtocol = privmode.Value
		conn.SecurityParameters = secparams.Copy()

		err := common.CheckConnection(&conn)
		if err != nil {
			log.Fatalf("%v", err)
		}

		err = conn.Connect()
		if err != nil {
			log.Fatalf("Connect() err: %v", err)
		}
		defer conn.Conn.Close()

		// get entPhysicalDescr
		result, err := common.BulkWalkToMap(&conn, entPhysicalDescrOID)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
			return
		}
		entPhysicalDescr := make(map[int]string)
		for it_index, it := range result {
			v, ok := it.(string)
			if !ok {
				fmt.Printf("Value for key %d is not a string: %v\n", it_index, it)
				continue
			}
			entPhysicalDescr[it_index] = v
		}

		// get entPhysicalClass
		result, err = common.BulkWalkToMap(&conn, entPhysicalClassOID)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
			return
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

		// get ps state - this is different depending on what type of device.
		// For now we use a flag provided by the user, maybe we want to check the model ourselves
		// at some stage in the future... or there might be a better way than model to check...
		var ciscoEnvMonSupplyState map[int]SnmpCiscoEnvMonState
		var cefcFruPowerOperStatus map[int]SnmpPowerOperType
		if psuBuiltIn {

			// get ciscoEnvMonSupplyState
			result, err = common.BulkWalkToMap(&conn, ciscoEnvMonSupplyStateOID)
			if err != nil {
				log.Fatalf("Error: %v\n", err)
				return
			}

			ciscoEnvMonSupplyState = make(map[int]SnmpCiscoEnvMonState)
			for it_index, it := range result {
				v, ok := it.(int)
				if !ok {
					fmt.Printf("Value for key %d is not an int: %v\n", it_index, it)
					continue
				}
				ciscoEnvMonSupplyState[it_index] = SnmpCiscoEnvMonState(v)
			}

		} else {

			// get cefcFruPowerOperStatus
			result, err = common.BulkWalkToMap(&conn, cefcFruPowerOperStatusOID)
			if err != nil {
				log.Fatalf("Error: %v\n", err)
				return
			}

			cefcFruPowerOperStatus = make(map[int]SnmpPowerOperType)
			for it_index, it := range result {
				v, ok := it.(int)
				if !ok {
					fmt.Printf("Value for key %d is not an int: %v\n", it_index, it)
					continue
				}
				cefcFruPowerOperStatus[it_index] = SnmpPowerOperType(v)
			}

		}

		var psuIndices []int
		for it_index, it := range entPhysicalClass {
			if it == IanaPhysicalClassPowerSupply {
				psuIndices = append(psuIndices, it_index)
			}
		}

		var psuContainers []int
		for it_index, it := range entPhysicalDescr {
			match, err := regexp.MatchString(`.*Power\ Supply.*Container.*`, it) // @Hardcoded
			if err != nil {
				fmt.Println("Error compiling regex: ", err)
			}
			if match {
				psuContainers = append(psuContainers, it_index)
			}
		}

		if len(psuContainers) == 0 {
			// ME-3800 at least needs this @Hack
			for it_index, it := range entPhysicalDescr {
				if it == "FRU Power Supply" {
					psuContainers = append(psuContainers, it_index)
				}
			}
		}

		var numberOfExpectedPsus int
		if psuExpectedOverrideValue > 0 {
			numberOfExpectedPsus = int(psuExpectedOverrideValue)
		} else if doubleContainers {
			numberOfExpectedPsus = 2 * len(psuContainers)
		} else {
			numberOfExpectedPsus = len(psuContainers)
		}

		numberOfPsus := len(psuIndices)
		switch {
		case numberOfPsus == numberOfExpectedPsus:
			if numberOfExpectedPsus == 1 {
				// it's only possible to get here if the device is online.
				common.ExitPlugin(&IcingaStatus{Value: IcingaOK, Message: fmt.Sprintf("All (%d) PSUs are present and 'ON'.", numberOfPsus)})
			}

			// Check PSUs have 'on' state
			for _, it := range psuIndices {
				if psuBuiltIn {
					if ciscoEnvMonSupplyState[it] != CiscoEnvMonStateNormal {
						common.ExitPlugin(&IcingaStatus{Value: IcingaWARN, Message: "At least one PSU is not 'ON'."})
					}
				} else {
					if cefcFruPowerOperStatus[it] != PowerOperTypeOn {
						common.ExitPlugin(&IcingaStatus{Value: IcingaWARN, Message: "At least one PSU is not 'ON'."})
					}
				}
			}
			common.ExitPlugin(&IcingaStatus{Value: IcingaOK, Message: fmt.Sprintf("All (%d) PSUs are present and 'ON'.", numberOfPsus)})
		case numberOfPsus == 1:
			common.ExitPlugin(&IcingaStatus{Value: IcingaWARN, Message: "Only one PSU is present."})
		case numberOfPsus < numberOfExpectedPsus:
			common.ExitPlugin(&IcingaStatus{Value: IcingaWARN, Message: fmt.Sprintf("Only %d PSUs are present (should be %d)", numberOfPsus, numberOfExpectedPsus)})
		case numberOfPsus == 0:
			common.ExitPlugin(&IcingaStatus{Value: IcingaCRITICAL, Message: "SNMP reports all PSUs are absent! (Huh?!)"})
		case numberOfPsus > numberOfExpectedPsus:
			common.ExitPlugin(&IcingaStatus{Value: IcingaWARN, Message: fmt.Sprintf("More PSUs (%d) than expecting (%d).", numberOfPsus, numberOfExpectedPsus)})
		default:
			common.ExitPlugin(&IcingaStatus{Value: IcingaUNKNOWN, Message: "Plugin error."})
		}

	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "Print debug information")

	// connection flags
	rootCmd.PersistentFlags().StringVarP(&conn.Target, "host", "H", "", "Hostname or IP address to run the check against (required)")
	rootCmd.MarkPersistentFlagRequired("host")
	rootCmd.PersistentFlags().Uint16VarP(&conn.Port, "port", "p", 161, "Port remote device SNMP agent is listening on")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 10, "Seconds to wait before timing out")

	// snmpv3 flags
	rootCmd.PersistentFlags().StringVarP(&secparams.UserName, "user", "u", "", "SNMPv3 user name (required)")
	rootCmd.MarkPersistentFlagRequired("user")
	rootCmd.PersistentFlags().VarP(&seclevel, "seclevel", "l", "SNMPv3 Security Level")
	rootCmd.PersistentFlags().StringVarP(&secparams.AuthenticationPassphrase, "authkey", "A", "", "SNMPv3 auth key (required)")
	rootCmd.MarkPersistentFlagRequired("authkey")
	rootCmd.PersistentFlags().StringVarP(&secparams.PrivacyPassphrase, "privkey", "X", "", "SNMPv3 priv key (required)")
	rootCmd.MarkPersistentFlagRequired("privkey")
	rootCmd.PersistentFlags().VarP(&authmode, "authmode", "a", "SNMPv3 Auth Mode")
	rootCmd.PersistentFlags().VarP(&privmode, "privmode", "x", "SNMPv3 Privacy Mode")

	// check specific flags
	rootCmd.PersistentFlags().BoolVar(&doubleContainers, "double-containers", false, "Some models report 1 container per powersupply (as you'd expect), others report 1 per switch. This flag is for the later.")
	rootCmd.PersistentFlags().BoolVar(&psuBuiltIn, "psu-built-in", false, "Some switches have built in PSUs, these need to be checked differently")
	rootCmd.PersistentFlags().Uint8Var(&psuExpectedOverrideValue, "expected-psu-override", 0, "Override expected number of PSUs (leave as 0 to determine automatically")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
