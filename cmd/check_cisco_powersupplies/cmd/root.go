package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"time"

	"github.com/jamiereid/go-icingaplugins/internal/pkg/common"
	. "github.com/jamiereid/go-icingaplugins/internal/pkg/common/types"

	"github.com/spf13/cobra"

	g "github.com/gosnmp/gosnmp"
)

var verbosity int
var conn g.GoSNMP
var secparams g.UsmSecurityParameters
var timeout int
var seclevel SnmpV3MsgFlagsValue
var authmode SnmpV3AuthProtocolValue
var privmode SnmpV3PrivProtocolValue
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
		common.SetupLogging(verbosity)
		ctx := context.Background() // just here so we can log using slog.Log() with common.LevelTrace
		slog.SetDefault(slog.With("target", conn.Target))

		conn.Version = g.Version3
		conn.SecurityModel = g.UserSecurityModel
		conn.MsgFlags = seclevel.Value
		conn.Timeout = time.Duration(timeout) * time.Second

		secparams.AuthenticationProtocol = authmode.Value
		secparams.PrivacyProtocol = privmode.Value
		conn.SecurityParameters = secparams.Copy()

		//
		// Some models need us to check different OIDs, or alter the way we determine
		// the quantity or status of power supplies.
		//

		deviceModelFamily, rawDeviceModel, err := common.GetDeviceModel(&conn)
		if err != nil {
			slog.Error("Problem when attempting to get the model of the device.", "error", err)
			os.Exit(1)
		}
		if *deviceModelFamily == CiscoModelFamilyUnknown {
			slog.Error("This application doesn't yet know how to handle this model.", "model", rawDeviceModel)
			os.Exit(1)
		}
		slog.SetDefault(slog.With("model", rawDeviceModel, "modelFamily", deviceModelFamily))

		var patternForPSUContainer *regexp.Regexp = regexp.MustCompile(`.*Power\ Supply.*Container.*`)

		modelRequiresAdditionalCheckForPSUIdentification := false // You must set patternForPSU if you set this to true
		var patternForPSU *regexp.Regexp

		modelRequiresContainersDoubled := false
		modelRequiresUseOfCiscoEnvMonSupplyStateTable := false
		modelHasOnlyOnePSU := false
		do9200Hack := false

		switch *deviceModelFamily {
		case CiscoModelFamily3750:
			modelRequiresContainersDoubled = true
		case CiscoModelFamily3750X:
			modelRequiresUseOfCiscoEnvMonSupplyStateTable = true
			modelRequiresContainersDoubled = true
		case CiscoModelFamily2960X:
			modelRequiresUseOfCiscoEnvMonSupplyStateTable = true
		case CiscoModelFamily2960, CiscoModelFamily3560:
			modelRequiresUseOfCiscoEnvMonSupplyStateTable = true
			modelHasOnlyOnePSU = true
		case CiscoModelFamily3800:
			modelRequiresUseOfCiscoEnvMonSupplyStateTable = true
			patternForPSUContainer = regexp.MustCompile(`^FRU\ Power\ Supply$`)
		case CiscoModelFamily4500:
			patternForPSUContainer = regexp.MustCompile(`^Container\ of\ Power\ Supply$`)
		case CiscoModelFamily6800:
			patternForPSUContainer = regexp.MustCompile(`^Chassis\ \d\ Container\ of\ Power\ Supply\ \d$`)
		case CiscoModelFamily9200:
			// :9200Hack
			// This model does not return any IanaPhysicalClassPowerSupply or containers, so we
			// need to @Hack around that...
			modelHasOnlyOnePSU = true
			do9200Hack = true
		case CiscoModelFamily9500:
			modelRequiresAdditionalCheckForPSUIdentification = true
			match, _ := regexp.MatchString(`^C9500-16.*$`, rawDeviceModel)
			if match {
				patternForPSU = regexp.MustCompile(`^Switch.*Power\ Supply\ [AB]$`)
			} else {
				patternForPSU = regexp.MustCompile(`^Cisco\ Catalyst\ 9500\ Series\s+\S+\s+\S+\s+Power\ Supply$`)
			}
		}

		var psuIndices []int
		var psuContainers []int
		var numberOfExpectedPsus int
		var ciscoEnvMonSupplyState map[int]SnmpCiscoEnvMonState
		var cefcFruPowerOperStatus map[int]SnmpPowerOperType

		if do9200Hack {
			psuIndices = append(psuIndices, 1)
			psuContainers = append(psuIndices, 1)
			numberOfExpectedPsus = 1
		} else {
			err = conn.Connect()
			if err != nil {
				slog.Error("Error occured when attempting to connect to device.", "target", &conn.Target, "error", err)
				os.Exit(1)
			}
			defer conn.Conn.Close()

			// get entPhysicalDescr
			result, err := common.BulkWalkToMap(&conn, entPhysicalDescrOID)
			if err != nil {
				slog.Error("BulkWalk of device failed.", "target", &conn.Target, "oid", entPhysicalDescrOID, "error", err)
				os.Exit(1)
			}
			entPhysicalDescr := make(map[int]string)
			for it_index, it := range result {
				v, ok := it.(string)
				if !ok {
					slog.Warn("Unable to convert value to string", "oid", entPhysicalDescrOID, "key", it_index, "raw_value", it)
					continue
				}
				entPhysicalDescr[it_index] = v
			}

			// get entPhysicalClass
			result, err = common.BulkWalkToMap(&conn, entPhysicalClassOID)
			if err != nil {
				slog.Error("BulkWalk of device failed.", "target", &conn.Target, "oid", entPhysicalClassOID, "error", err)
				os.Exit(1)
			}
			entPhysicalClass := make(map[int]SnmpIanaPhysicalClass)
			for it_index, it := range result {
				v, ok := it.(int)
				if !ok {
					slog.Warn("Unable to convert value to int", "oid", entPhysicalDescrOID, "key", it_index, "raw_value", it)
					continue
				}
				entPhysicalClass[it_index] = SnmpIanaPhysicalClass(v)
			}

			if modelRequiresUseOfCiscoEnvMonSupplyStateTable {
				slog.Debug("Detected model has set modelRequiresUseOfCiscoEnvMonSupplyStateTable")

				// get ciscoEnvMonSupplyState
				result, err = common.BulkWalkToMap(&conn, ciscoEnvMonSupplyStateOID)
				if err != nil {
					slog.Error("BulkWalk of device failed.", "target", &conn.Target, "oid", ciscoEnvMonSupplyStateOID, "error", err)
					os.Exit(1)
				}

				ciscoEnvMonSupplyState = make(map[int]SnmpCiscoEnvMonState)
				for it_index, it := range result {
					v, ok := it.(int)
					if !ok {
						slog.Warn("Unable to convert value to int", "oid", ciscoEnvMonSupplyStateOID, "key", it_index, "raw_value", it)
						continue
					}
					ciscoEnvMonSupplyState[it_index] = SnmpCiscoEnvMonState(v)
				}

			} else {
				slog.Debug("Using cefcFruPowerOperStatus to determine status")

				// get cefcFruPowerOperStatus
				result, err = common.BulkWalkToMap(&conn, cefcFruPowerOperStatusOID)
				if err != nil {
					slog.Error("BulkWalk of device failed.", "target", &conn.Target, "oid", cefcFruPowerOperStatusOID, "error", err)
					os.Exit(1)
				}

				cefcFruPowerOperStatus = make(map[int]SnmpPowerOperType)
				for it_index, it := range result {
					v, ok := it.(int)
					if !ok {
						slog.Warn("Unable to convert value to int", "oid", cefcFruPowerOperStatusOID, "key", it_index, "raw_value", it)
						continue
					}
					cefcFruPowerOperStatus[it_index] = SnmpPowerOperType(v)
				}

			}

			for it_index, it := range entPhysicalClass {
				l := slog.With("entPhysicalClass", it, "id", it_index)
				if it == IanaPhysicalClassPowerSupply {
					l.Debug("found power supply")
					if modelRequiresAdditionalCheckForPSUIdentification {
						l.Debug("Detected model has set modelRequiresAdditionalCheckForPS")
						if !patternForPSU.MatchString(entPhysicalDescr[it_index]) {
							l.Debug("additional check did not pass", "pattern", patternForPSU.String())
							continue
						}
						l.Debug("additional check has passed", "pattern", patternForPSU.String())
					}
					l.Debug("adding power supply")
					psuIndices = append(psuIndices, it_index)
				}
			}

			for it_index, it := range entPhysicalDescr {
				l := slog.With("pattern", patternForPSUContainer.String(), "string", it)
				l.Log(ctx, common.LevelTrace, "Testing for psu container")
				if patternForPSUContainer.MatchString(it) {
					l.Debug("Matched psu container")
					psuContainers = append(psuContainers, it_index)
				}
			}

			if modelHasOnlyOnePSU {
				slog.Debug("Detected model has set modelHasOnlyOnePSU")
				stackMembers, err := common.GetStackMembers(&conn)
				if err != nil {
					slog.Error(fmt.Sprintf("%v", err))
					os.Exit(1)
				}
				numberOfExpectedPsus = 1 * len(stackMembers)
			} else if psuExpectedOverrideValue > 0 {
				slog.Debug("User set PSU expected value as argument", "psuExpectedOverrideValue", psuExpectedOverrideValue)
				numberOfExpectedPsus = int(psuExpectedOverrideValue)
			} else if modelRequiresContainersDoubled {
				numberOfExpectedPsus = 2 * len(psuContainers)
				slog.Debug("Detected model has set modelRequiresContainersDoubled", "len(psuContainers)", len(psuContainers), "numberOfExpectedPsus", numberOfExpectedPsus)
			} else {
				numberOfExpectedPsus = len(psuContainers)
				slog.Debug("No manipulation of expected PSU total", "numberOfExpectedPsus", numberOfExpectedPsus)
			}
		} // end do9200Hack else

		numberOfPsus := len(psuIndices)
		switch {
		case (numberOfPsus == numberOfExpectedPsus) || (psuExpectedOverrideValue > 0):
			if numberOfExpectedPsus == 1 {
				// it's only possible to get here if the device is online.
				common.ExitPlugin(&IcingaStatus{Value: IcingaOK, Message: fmt.Sprintf("All (%d) PSUs are present and 'ON'.", numberOfExpectedPsus)})
			}

			// Check PSUs have 'on' state
			for _, it := range psuIndices {
				l := slog.With("index", it)
				if modelRequiresUseOfCiscoEnvMonSupplyStateTable {
					l.Debug("Detected model has set modelRequiresUseOfCiscoEnvMonSupplyStateTable")
					l.Debug("Testing psu state, looking for CiscoEnvMonStateNormal", "ciscoEnvMonSupplyState[it]", ciscoEnvMonSupplyState[it])
					if ciscoEnvMonSupplyState[it] != CiscoEnvMonStateNormal {
						common.ExitPlugin(&IcingaStatus{Value: IcingaWARN, Message: "At least one PSU is not 'ON'."})
					}
				} else {
					l.Debug("Testing psu status, looking for PowerOperTypeOn", "cefcFruPowerOperStatus[it]", cefcFruPowerOperStatus[it])
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
	rootCmd.PersistentFlags().CountVarP(&verbosity, "verbose", "v", "Increase verbosity (-v, -vv, -vvv)")

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
	rootCmd.PersistentFlags().Uint8Var(&psuExpectedOverrideValue, "expected-psu-override", 0, "Override expected number of PSUs (leave as 0 to determine automatically")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
