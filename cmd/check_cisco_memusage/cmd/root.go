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

const cpmCpuMemoryUsedOID string = "1.3.6.1.4.1.9.9.109.1.1.1.1.12"
const cpmCpuMemoryFreeOID string = "1.3.6.1.4.1.9.9.109.1.1.1.1.13"
const ciscoMemoryPoolUsedOID string = "1.3.6.1.4.1.9.9.48.1.1.1.5"
const ciscoMemoryPoolFreeOID string = "1.3.6.1.4.1.9.9.48.1.1.1.6"

var Debug bool
var conn g.GoSNMP
var secparams g.UsmSecurityParameters
var timeout int
var seclevel SnmpV3MsgFlagsValue
var authmode SnmpV3AuthProtocolValue
var privmode SnmpV3PrivProtocolValue

var mib MemoryMibValue
var warningThreshold uint32
var criticalThreshold uint32

var rootCmd = &cobra.Command{
	Use:   "check_cisco_memusage",
	Short: "Cisco memory usage check plugin",
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

		var memMib string
		var freeMib string
		switch mib.Value {
		case MemoryMibCiscoProcessMib:
			memMib = cpmCpuMemoryUsedOID
			freeMib = cpmCpuMemoryFreeOID
		case MemoryMibCiscoMemoryPoolMib:
			memMib = ciscoMemoryPoolUsedOID
			freeMib = ciscoMemoryPoolFreeOID
		}

		// get memory used
		result, err := common.BulkWalkToMap(&conn, memMib)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
			return
		}
		memUsed := make(map[int]uint32)
		for k, v := range result {
			val, ok := v.(uint32)
			if !ok {
				fmt.Printf("Value for key %d is not a string: %v\n", k, v)
				continue
			}
			memUsed[k] = val
		}

		// get memory free
		result, err = common.BulkWalkToMap(&conn, freeMib)
		if err != nil {
			log.Fatalf("Error: %v\n", err)
			return
		}
		memFree := make(map[int]uint32)
		for k, v := range result {
			val, ok := v.(uint32)
			if !ok {
				fmt.Printf("Value for key %d is not a string: %v\n", k, v)
				continue
			}
			memFree[k] = val
		}

		// CISCO-MEMORY-POOL-MIB reports bytes, not kilobytes
		if mib.Value == MemoryMibCiscoMemoryPoolMib {
			for k, v := range memUsed {
				memUsed[k] = v / 1024
			}

			for k, v := range memFree {
				memFree[k] = v / 1024
			}
		}

		// Assume everything is ok, then check this assumption
		var exitStatus IcingaStatusVal = IcingaOK
		var perfData strings.Builder
		var exitMsg strings.Builder

		for id, val := range memFree {
			// Calculate total memory and thresholds
			total := val + memUsed[id]
			warn_at := total * (warningThreshold / 100)
			crit_at := total * (criticalThreshold / 100)
			usedPercent := math.Round((float64(val) / float64(total)) * 100)

			perfData.WriteString(fmt.Sprintf("'mem_used_%v'=%vKB;%v;%v;0;%d ", id, memUsed[id], warn_at, crit_at, total))
			exitMsg.WriteString(fmt.Sprintf("Memory (%v): %v%%, ", id, usedPercent))

			// check thresholds
			if memUsed[id] >= crit_at {
				exitStatus = IcingaCRITICAL
			}

			if exitStatus != IcingaCRITICAL && memUsed[id] >= warn_at {
				exitStatus = IcingaWARN
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
	rootCmd.PersistentFlags().VarP(&mib, "mib", "m", "use OIDs from this MIB")
	rootCmd.PersistentFlags().Uint32VarP(&warningThreshold, "warn", "w", 70, "warning threshold (in percent)")
	rootCmd.PersistentFlags().Uint32VarP(&criticalThreshold, "crit", "c", 80, "critical threshold (in percent)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
