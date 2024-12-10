package cmd

import (
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"github.com/jamiereid/go-icingaplugins/internal/pkg/common"
	. "github.com/jamiereid/go-icingaplugins/internal/pkg/common/types"

	"github.com/spf13/cobra"

	g "github.com/gosnmp/gosnmp"
)

const ciscoEnvMonTemperatureStatusValueOID string = "1.3.6.1.4.1.9.9.13.1.3.1.3" // returns gauge32
const ciscoEnvMonTemperatureThesholdOID string = "1.3.6.1.4.1.9.9.13.1.3.1.4"    // returns integer32
const ciscoEnvMonTemperatureStateOID string = "1.3.6.1.4.1.9.9.13.1.3.1.6"       // returns ciscoenvmovstate

var Debug bool
var conn g.GoSNMP
var secparams g.UsmSecurityParameters
var timeout int
var seclevel SnmpV3MsgFlagsValue
var authmode SnmpV3AuthProtocolValue
var privmode SnmpV3PrivProtocolValue

// var switchOS CiscoOSValue
var scaleFactorAsPercent uint32

var rootCmd = &cobra.Command{
	Use:   "check_cisco_envtemp",
	Short: "Cisco temperature sensors check plugin",
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

		// "IF" CISCO IOS
		// could we switch on switchOS here to set which mib we use, like we did in memory check?

		// get temperature values
		result, err := common.BulkWalkToMap(&conn, ciscoEnvMonTemperatureStatusValueOID)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
			return
		}
		temperatureValues := make(map[int]uint32)
		for it_index, it := range result {
			val, ok := it.(uint32)
			if !ok {
				fmt.Printf("Value for key %d is not a uint32: %v\n", it_index, it)
				continue
			}
			temperatureValues[it_index] = val
		}

		// get vendor defined thresholds
		result, err = common.BulkWalkToMap(&conn, ciscoEnvMonTemperatureThesholdOID)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
			return
		}
		temperatureThresholds := make(map[int]uint32)
		for it_index, it := range result {
			val, ok := it.(int)
			if !ok {
				fmt.Printf("Value for key %d is not a int: %v\n", it_index, it)
				continue
			}
			temperatureThresholds[it_index] = uint32(val)
		}

		// Assume everything is ok, then check this assumption
		var exitStatus IcingaStatusVal = IcingaOK
		var perfData strings.Builder
		var exitMsg strings.Builder

		exitMsg.WriteString("Sensor readings are: ")

		for it_index, it := range temperatureValues {
			if scaleFactorAsPercent != 0 || scaleFactorAsPercent == 100 { // prevent divide by 0, and unnecessary work
				temperatureThresholds[it_index] = uint32(math.Round(float64(temperatureThresholds[it_index]) * (float64(scaleFactorAsPercent) / 100)))
			}

			perfData.WriteString(fmt.Sprintf("'temp_%v'=%v;;%v;; ", it_index, it, temperatureThresholds[it_index]))
			exitMsg.WriteString(fmt.Sprintf("%v°C, ", it))

			if exitStatus == IcingaCRITICAL {
				continue
			}

			if it >= temperatureThresholds[it_index] && temperatureThresholds[it_index] != 0 {
				exitStatus = IcingaCRITICAL
			}
		}

		// @SPEED
		exitMsgString := strings.TrimSuffix(exitMsg.String(), ", ")

		common.ExitPlugin(&IcingaStatus{Value: exitStatus, Message: exitMsgString, PerfData: perfData.String()})

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
	//rootCmd.PersistentFlags().Var(&switchOS, "os", "Switch operating system")
	rootCmd.PersistentFlags().Uint32Var(&scaleFactorAsPercent, "scale", 100, "scaling factor for thresholds (in percent)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
