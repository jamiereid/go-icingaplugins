package cmd

import (
	"fmt"
	"log"
	"os"
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

const cswSwitchStateOID string = "1.3.6.1.4.1.9.9.500.1.2.1.1.6"
const cswStackPowerPortLinkStatusOID string = "1.3.6.1.4.1.9.9.500.1.3.2.1.5"

var rootCmd = &cobra.Command{
	Use:   "check_cisco_powerstack",
	Short: "Cisco power stack check plugin",
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

		// get cswSwitchState (switch module states)
		result, err := common.BulkWalkToMap(&conn, cswSwitchStateOID)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
			return
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
			log.Fatalf("Error: %v\n", err)
			return
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
		var exitMsg string

		// @NOTE: this is not exhaustive, it has an @ASSUMPTION that this plug only ever exits WARN or OK
		switch exitStatus {
		case IcingaWARN:
			exitMsg = fmt.Sprintf("Switch states: \"%s\", Power stack port statuses: \"%s\"", switchStates, stackPowerPortStatuses)
		case IcingaOK:
			exitMsg = fmt.Sprintf("%d switches are \"ready\" and %d power stack ports are up", len(switchStates), len(stackPowerPortStatuses))
		}

		common.ExitPlugin(&IcingaStatus{Value: exitStatus, Message: exitMsg})

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
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
