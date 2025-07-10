package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
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
var maxTimesToRetryModelQuery uint8

const cswSwitchStateOID string = "1.3.6.1.4.1.9.9.500.1.2.1.1.6"
const cswStatePortOperStatusOID string = "1.3.6.1.4.1.9.9.500.1.2.2.1.1"
const ifDescrOID = "1.3.6.1.2.1.2.2.1.2"
const ifAliasOID string = "1.3.6.1.2.1.31.1.1.1.18"
const ifAdminStatusOID string = "1.3.6.1.2.1.2.2.1.7"
const ifOperStatusOID string = "1.3.6.1.2.1.2.2.1.8"

var rootCmd = &cobra.Command{
	Use:   "check_cisco_stackmodules",
	Short: "Cisco data stack check plugin",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		common.SetupLogging(verbosity)
		//ctx := context.Background() // just here so we can log using slog.Log() with common.LevelTrace
		slog.SetDefault(slog.With("target", conn.Target))
		slog.Debug("Verbosity level set from cli argument", "verbosity", verbosity)

		conn.Version = g.Version3
		conn.SecurityModel = g.UserSecurityModel
		conn.MsgFlags = seclevel.Value
		conn.Timeout = time.Duration(timeout) * time.Second

		secparams.AuthenticationProtocol = authmode.Value
		secparams.PrivacyProtocol = privmode.Value
		conn.SecurityParameters = secparams.Copy()

		//
		// Some models need us to check different OIDs.
		//
		// Sometimes, this initial call can succeed, but return an empty response - which
		// stops us from proceeding. Hence, this retry code.

		var (
			deviceModelFamily *CiscoModelFamily
			rawDeviceModel    string
			err               error
		)

		slog.Debug("Begin attempt to get model from device.")
		for attempt := 1; attempt <= int(maxTimesToRetryModelQuery); attempt++ {
			deviceModelFamily, rawDeviceModel, err = common.GetDeviceModel(&conn)
			if err != nil {
				slog.Error("Problem when attempting to get the model of the device.", "error", err)
				os.Exit(1)
			}

			if rawDeviceModel != "" {
				break // success
			}

			slog.Warn("Got empty model string; retrying...", "attempt", attempt)
			time.Sleep(500 * time.Millisecond)
		}
		slog.Debug("End attempt to get model from device.")

		if *deviceModelFamily == CiscoModelFamilyUnknown {
			var message string
			if rawDeviceModel != "" {
				message = "This application doesn't yet know how to handle this model."
			} else {
				message = "Recieved an empty string when quering for the model multiple times."
			}
			slog.Error(message, "model", rawDeviceModel)
			os.Exit(1)
		}
		slog.SetDefault(slog.With("model", rawDeviceModel, "modelFamily", deviceModelFamily))
		slog.Debug("Past model check, proceeding...")

		err = conn.Connect()
		if err != nil {
			slog.Error("Error occured when attempting to connect to device.", "error", err)
			os.Exit(1)
		}
		defer conn.Conn.Close()
		slog.Debug("We have a connection to the device...")

		// before we start to check the stack state, we should know what type of stack it is
		traditionalStack := true
		slog.Debug("Beginning to determine what type of stack we're dealing with, assuming a 'traditional' stack to start with.", "traditionalStack", traditionalStack)
		cswStackTypeOID := "1.3.6.1.4.1.9.9.500.1.1.7.0" // @Note .0 is @Hardcoded here and might not be right everywhere?
		stackTypeRaw, err := common.SnmpGet(&conn, cswStackTypeOID)
		if err != nil {
			if err.Error() != "SNMP Response: No Such Object" {
				slog.Error("Error while attempting to get stack type.", "oid", cswStackTypeOID, "error", err)
				os.Exit(1)
			}
		} else {
			stackType := stackTypeRaw.(uint32) // @Assumption

			if stackType > 0 {
				// *probably* a stackwise virtual
				traditionalStack = false
				slog.Debug("stackType reported as higher than 0, we're dealing with something that isn't a traditional stack", "stackType", stackType)
			}
		}
		slog.Debug("Stack type decision made, continuing...", "traditionalStack", traditionalStack)

		// get cswSwitchState (switch module states)
		slog.Debug("Beginning attempt to get the switch module states via snmp")
		result, err := common.BulkWalkToMap(&conn, cswSwitchStateOID)
		if err != nil {
			slog.Error("BulkWalk of device failed.", "oid", cswSwitchStateOID, "error", err)
			os.Exit(1)
		}
		cswSwitchState := make(map[int]SnmpCswSwitchState)
		for it_index, it := range result {
			v, ok := it.(int)
			if !ok {
				slog.Warn("Unable to convert value to int", "oid", cswStackTypeOID, "key", it_index, "raw_value", it)
				continue
			}
			cswSwitchState[it_index] = SnmpCswSwitchState(v)
		}
		slog.Debug("We have the switch module states.")

		// Assume everything is ok, then check this assumption (See Exit below is changing this code)
		var exitStatus IcingaStatusVal = IcingaOK
		var stackPortStatuses []SnmpCswStackPortOperStatus
		var svlIfStatuses []SnmpIfOperStatus
		if traditionalStack {
			// get cswStackPortOperStatus (stack port state)
			slog.Debug("Beginning attempt to get stack ports operational statuses", "traditionalStack", traditionalStack, "oid", cswStatePortOperStatusOID)
			result, err = common.BulkWalkToMap(&conn, cswStatePortOperStatusOID)
			if err != nil {
				slog.Error("BulkWalk of device failed.", "oid", cswStatePortOperStatusOID, "error", err)
				os.Exit(1)
			}
			cswStackPortOperStatus := make(map[int]SnmpCswStackPortOperStatus)
			for it_index, it := range result {
				v, ok := it.(int)
				if !ok {
					slog.Warn("Unable to convert value to int", "oid", cswStatePortOperStatusOID, "key", it_index, "raw_value", it)
					continue
				}
				cswStackPortOperStatus[it_index] = SnmpCswStackPortOperStatus(v)
			}

			for _, it := range cswStackPortOperStatus {
				if it != SnmpCswStackPortOperStatusUp && exitStatus != IcingaWARN {
					exitStatus = IcingaWARN
				}
				stackPortStatuses = append(stackPortStatuses, it)
			}
		} else { // @Assumption: stackwise virtual
			// get all the interface descriptions, and find the ones that *likely* the SVLs
			// unfortunatly, I haven't found a MIB that will clearly tell us the members, so
			// we do the best we can - which isn't that good :(

			slog.Debug("Beginning attempt to get stack ports operational statuses on what we're assuming is a stackwise virtual stack", "traditionalStack", traditionalStack)
			result, err := common.BulkWalkToMap(&conn, ifAliasOID)
			if err != nil {
				slog.Error("BulkWalk of device failed.", "oid", ifAliasOID, "error", err)
				os.Exit(1)
			}
			interestingStrings := []string{"svl", "vsl"}
			var svlInterfaceIDs []int
			for it_index, it := range result {
				strIt, ok := it.(string)
				if !ok {
					slog.Warn("Skipping key, value is not a string", "key", it_index)
					continue
				}

				strIt = strings.ToLower(strIt)

				for _, needle := range interestingStrings {
					if strings.Contains(strIt, needle) {
						svlInterfaceIDs = append(svlInterfaceIDs, it_index)
						break
					}
				}
			}

			// get ifAdminStatus
			result, err = common.BulkWalkToMap(&conn, ifAdminStatusOID)
			if err != nil {
				slog.Error("BulkWalk of device failed.", "oid", ifAdminStatusOID, "error", err)
				os.Exit(1)
			}
			ifAdminStatus := make(map[int]SnmpIfAdminStatus)
			for it_index, it := range result {
				v, ok := it.(int)
				if !ok {
					slog.Warn("Unable to convert value to int", "oid", ifAdminStatusOID, "key", it_index, "raw_value", it)
					continue
				}
				ifAdminStatus[it_index] = SnmpIfAdminStatus(v)
			}

			// get ifOperStatus
			result, err = common.BulkWalkToMap(&conn, ifOperStatusOID)
			if err != nil {
				slog.Error("BulkWalk of device failed.", "oid", ifOperStatusOID, "error", err)
				os.Exit(1)
			}
			ifOperStatus := make(map[int]SnmpIfOperStatus)
			for it_index, it := range result {
				v, ok := it.(int)
				if !ok {
					slog.Warn("Unable to convert value to int", "oid", ifOperStatusOID, "key", it_index, "raw_value", it)
					continue
				}
				ifOperStatus[it_index] = SnmpIfOperStatus(v)
			}

			// check the status of assumed svl interfaces
			for _, it := range svlInterfaceIDs {
				if ifAdminStatus[it] != IfAdminStatusUp && ifOperStatus[it] != IfOperStatusUp && exitStatus != IcingaWARN {
					exitStatus = IcingaWARN
				}
				svlIfStatuses = append(svlIfStatuses, ifOperStatus[it])
			}

		}

		var switchStates []SnmpCswSwitchState
		for _, it := range cswSwitchState {
			if it != SnmpCswSwitchStateReady && exitStatus != IcingaWARN {
				exitStatus = IcingaWARN
			}
			switchStates = append(switchStates, it)
		}

		// Exit
		var exitMsg strings.Builder

		// @Note: this is not exhaustive, it has an @Assumption that this plug in only ever exits WARN or OK
		switch exitStatus {
		case IcingaWARN:

			exitMsg.WriteString("Switch states are \"")
			for it_index, it := range switchStates {
				if it_index > 0 {
					exitMsg.WriteString(", ")
				}
				exitMsg.WriteString(strings.TrimPrefix(it.String(), "SnmpCswSwitchState")) // @Speed
			}

			if traditionalStack {
				exitMsg.WriteString("\"; Stack port statuses are \"")
				for it_index, it := range stackPortStatuses {
					if it_index > 0 {
						exitMsg.WriteString(", ")
					}
					exitMsg.WriteString(strings.TrimPrefix(it.String(), "SnmpCswStackPortOperState")) // @Speed
				}
			} else {
				// @Assumption stackwise virtual
				exitMsg.WriteString("\"; SVL interface statuses are \"")
				for it_index, it := range svlIfStatuses {
					if it_index > 0 {
						exitMsg.WriteString(", ")
					}
					exitMsg.WriteString(strings.TrimPrefix(it.String(), "SnmpIfOperStatus")) // @Speed
				}
			}

			exitMsg.WriteString("\"")

		case IcingaOK:
			if traditionalStack {
				exitMsg.WriteString(fmt.Sprintf("%d switches are \"ready\" and %d stack ports are up", len(switchStates), len(stackPortStatuses)))
			} else {
				// @Assumption stackwise virtual
				exitMsg.WriteString(fmt.Sprintf("%d switches are \"ready\" and %d SVL interfaces are up", len(switchStates), len(svlIfStatuses)))
			}
		}

		common.ExitPlugin(&IcingaStatus{Value: exitStatus, Message: exitMsg.String()})

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

	rootCmd.PersistentFlags().Uint8Var(&maxTimesToRetryModelQuery, "max-model-query-retries", 2, "How many times to retry the initial query for model (at half second intervals)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
