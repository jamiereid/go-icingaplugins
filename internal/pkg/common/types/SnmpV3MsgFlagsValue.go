package types

import (
	"errors"
	"strings"

	g "github.com/gosnmp/gosnmp"
)

// SnmpV3MsgFlagsValue is a custom flag type for g.SnmpV3MsgFlags
type SnmpV3MsgFlagsValue struct {
	Value g.SnmpV3MsgFlags
}

var validValuesSnmpV3MsgFlagsValue = map[string]g.SnmpV3MsgFlags{
	"noauthnopriv": g.NoAuthNoPriv,
	"authnopriv":   g.AuthNoPriv,
	"authpriv":     g.AuthPriv,
}

func (s *SnmpV3MsgFlagsValue) String() string {
	for k, v := range validValuesSnmpV3MsgFlagsValue {
		if v == s.Value {
			return k
		}
	}
	return ""
}

// Set parses and sets the value from a string
func (s *SnmpV3MsgFlagsValue) Set(value string) error {
	if flag, ok := validValuesSnmpV3MsgFlagsValue[strings.ToLower(value)]; ok {
		s.Value = flag
		return nil
	}
	return errors.New("invalid value for SnmpV3MsgFlags, valid options are: " +
		strings.Join(s.validKeys(), ", "))
}

func (s *SnmpV3MsgFlagsValue) Type() string {
	return "SnmpV3MsgFlags"
}

// validKeys returns a slice of valid keys for error messages
func (s *SnmpV3MsgFlagsValue) validKeys() []string {
	keys := make([]string, 0, len(validValuesSnmpV3MsgFlagsValue))
	for k := range validValuesSnmpV3MsgFlagsValue {
		keys = append(keys, k)
	}
	return keys
}
