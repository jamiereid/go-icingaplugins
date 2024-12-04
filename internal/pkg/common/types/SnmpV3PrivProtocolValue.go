package types

import (
	"errors"
	"strings"

	g "github.com/gosnmp/gosnmp"
)

// SnmpV3PrivProtocolValue is a custom flag type for g.SnmpV3PrivProtocol
type SnmpV3PrivProtocolValue struct {
	Value g.SnmpV3PrivProtocol
}

var validValuesSnmpV3PrivProtocol = map[string]g.SnmpV3PrivProtocol{
	"nopriv":  g.NoPriv,
	"des":     g.DES,
	"aes":     g.AES,
	"aes192":  g.AES192,
	"aes256":  g.AES256,
	"aes192c": g.AES192C,
	"aes256c": g.AES256C,
}

func (s *SnmpV3PrivProtocolValue) String() string {
	for k, v := range validValuesSnmpV3PrivProtocol {
		if v == s.Value {
			return k
		}
	}
	return ""
}

// Set parses and sets the value from a string
func (s *SnmpV3PrivProtocolValue) Set(value string) error {
	if flag, ok := validValuesSnmpV3PrivProtocol[strings.ToLower(value)]; ok {
		s.Value = flag
		return nil
	}
	return errors.New("invalid value for SnmpV3MsgFlags, valid options are: " +
		strings.Join(s.validKeys(), ", "))
}

func (s *SnmpV3PrivProtocolValue) Type() string {
	return "SnmpV3Protocol"
}

// validKeys returns a slice of valid keys for error messages
func (s *SnmpV3PrivProtocolValue) validKeys() []string {
	keys := make([]string, 0, len(validValuesSnmpV3PrivProtocol))
	for k := range validValuesSnmpV3PrivProtocol {
		keys = append(keys, k)
	}
	return keys
}
