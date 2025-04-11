package cmd

import (
	"fmt"
	"log/slog"
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
var maxTimesToRetryModelQuery uint8

var warningThreshold uint32
var criticalThreshold uint32

var rootCmd = &cobra.Command{
	Use:   "check_cisco_memusage",
	Short: "Cisco memory usage check plugin",
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

		using_mib := MemoryMibCiscoProcessMib
		used_memory_mib := cpmCpuMemoryUsedOID
		free_memory_mib := cpmCpuMemoryFreeOID

		switch *deviceModelFamily {
		case CiscoModelFamily2960:
		case CiscoModelFamily2960X:
		case CiscoModelFamily3560:
		case CiscoModelFamily3750X:
		case CiscoModelFamily3800:
		case CiscoModelFamily6800:
			using_mib = MemoryMibCiscoMemoryPoolMib
			used_memory_mib = ciscoMemoryPoolUsedOID
			free_memory_mib = ciscoMemoryPoolFreeOID
		}

		err = conn.Connect()
		if err != nil {
			slog.Error("Error occured when attempting to connect to device.", "error", err)
			os.Exit(1)
		}
		defer conn.Conn.Close()

		// get memory used
		result, err := common.BulkWalkToMap(&conn, used_memory_mib)
		if err != nil {
			slog.Error("BulkWalk of device failed.", "oid", used_memory_mib, "error", err)
			os.Exit(1)
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
		result, err = common.BulkWalkToMap(&conn, free_memory_mib)
		if err != nil {
			slog.Error("BulkWalk of device failed.", "oid", free_memory_mib, "error", err)
			os.Exit(1)
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
		if using_mib == MemoryMibCiscoMemoryPoolMib {
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
	rootCmd.PersistentFlags().Uint32VarP(&warningThreshold, "warn", "w", 70, "warning threshold (in percent)")
	rootCmd.PersistentFlags().Uint32VarP(&criticalThreshold, "crit", "c", 80, "critical threshold (in percent)")
	rootCmd.PersistentFlags().Uint8Var(&maxTimesToRetryModelQuery, "max-model-query-retries", 2, "How many times to retry the initial query for model (at half second intervals)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
