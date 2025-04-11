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

var Debug bool
var conn g.GoSNMP
var secparams g.UsmSecurityParameters
var timeout int
var seclevel SnmpV3MsgFlagsValue
var authmode SnmpV3AuthProtocolValue
var privmode SnmpV3PrivProtocolValue
var maxTimesToRetryModelQuery uint8

var doubleContainers bool
var psuBuiltIn bool

const cswSwitchStateOID string = "1.3.6.1.4.1.9.9.500.1.2.1.1.6"
const cswStackPowerPortLinkStatusOID string = "1.3.6.1.4.1.9.9.500.1.3.2.1.5"

var rootCmd = &cobra.Command{
	Use:   "check_cisco_powerstack",
	Short: "Cisco power stack check plugin",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		slog.SetDefault(slog.With("target", conn.Target))

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

		err = conn.Connect()
		if err != nil {
			slog.Error("Problem with connecting to the device", "error", err)
			os.Exit(1)
		}
		defer conn.Conn.Close()

		// get cswSwitchState (switch module states)
		result, err := common.BulkWalkToMap(&conn, cswSwitchStateOID)
		if err != nil {
			slog.Error("BulkWalk of device failed.", "oid", cswSwitchStateOID, "error", err)
			os.Exit(1)
		}
		cswSwitchState := make(map[int]SnmpCswSwitchState)
		for k, v := range result {
			v, ok := v.(int)
			if !ok {
				fmt.Printf("Value for key %d is not an int: %v\n", k, v)
				continue
			}
			cswSwitchState[k] = SnmpCswSwitchState(v)
		}

		// get cswStackPowerPortLinkStatus (stack power port state)
		result2, err := common.BulkWalkToStringMap(&conn, cswStackPowerPortLinkStatusOID)
		if err != nil {
			slog.Error("BulkWalk of device failed.", "oid", cswStackPowerPortLinkStatusOID, "error", err)
			os.Exit(1)
		}
		cswStackPowerPortLinkStatus := make(map[string]SnmpCswStackPowerPortLinkStatus)
		for k, v := range result2 {
			v, ok := v.(int)
			if !ok {
				fmt.Printf("Value for key %s is not an int: %v\n", k, v)
				continue
			}
			cswStackPowerPortLinkStatus[k] = SnmpCswStackPowerPortLinkStatus(v)
		}

		// Assume everything is ok, then check this assumption (See Exit below is changing this code)
		var exitStatus IcingaStatusVal = IcingaOK
		var switchStates []SnmpCswSwitchState
		var stackPowerPortStatuses []SnmpCswStackPowerPortLinkStatus

		for _, v := range cswSwitchState {
			if v != SnmpCswSwitchStateReady && exitStatus != IcingaWARN {
				exitStatus = IcingaWARN
			}
			switchStates = append(switchStates, v)
		}

		for _, v := range cswStackPowerPortLinkStatus {
			if v != SnmpCswStackPowerPortLinkStatusUp && exitStatus != IcingaWARN {
				exitStatus = IcingaWARN
			}
			stackPowerPortStatuses = append(stackPowerPortStatuses, v)
		}

		// Exit
		var exitMsg strings.Builder

		// @NOTE: this is not exhaustive, it has an @ASSUMPTION that this plug only ever exits WARN or OK
		switch exitStatus {
		case IcingaWARN:

			exitMsg.WriteString("Switch states are \"")
			for it_index, it := range switchStates {
				if it_index > 0 {
					exitMsg.WriteString(", ")
				}
				exitMsg.WriteString(strings.TrimPrefix(it.String(), "SnmpCswSwitchState")) // @Speed
			}

			exitMsg.WriteString("\"; Stack power port statuses are \"")
			for it_index, it := range stackPowerPortStatuses {
				if it_index > 0 {
					exitMsg.WriteString(", ")
				}
				exitMsg.WriteString(strings.TrimPrefix(it.String(), "SnmpCswStackPortOperState")) // @Speed
			}

			exitMsg.WriteString("\"")

		case IcingaOK:
			exitMsg.WriteString(fmt.Sprintf("%d switches are \"ready\" and %d power stack ports are up", len(switchStates), len(stackPowerPortStatuses)))
		}

		common.ExitPlugin(&IcingaStatus{Value: exitStatus, Message: exitMsg.String()})

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
	rootCmd.PersistentFlags().Uint8Var(&maxTimesToRetryModelQuery, "max-model-query-retries", 2, "How many times to retry the initial query for model (at half second intervals)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
