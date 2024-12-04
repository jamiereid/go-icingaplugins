package types

import (
	"errors"
	"strings"

	g "github.com/gosnmp/gosnmp"
)

// SnmpV3AuthProtocolValue is a custom flag type for g.SnmpV3AuthProtocol
type SnmpV3AuthProtocolValue struct {
	Value g.SnmpV3AuthProtocol
}

var validValuesSnmpV3AuthProtocol = map[string]g.SnmpV3AuthProtocol{
	"noauth": g.NoAuth,
	"md5":    g.MD5,
	"sha":    g.SHA,
	"sha224": g.SHA224,
	"sha256": g.SHA256,
	"sha384": g.SHA384,
	"sha512": g.SHA512,
}

func (s *SnmpV3AuthProtocolValue) String() string {
	for k, v := range validValuesSnmpV3AuthProtocol {
		if v == s.Value {
			return k
		}
	}
	return ""
}

// Set parses and sets the value from a string
func (s *SnmpV3AuthProtocolValue) Set(value string) error {
	if flag, ok := validValuesSnmpV3AuthProtocol[strings.ToLower(value)]; ok {
		s.Value = flag
		return nil
	}
	return errors.New("invalid value for SnmpV3MsgFlags, valid options are: " +
		strings.Join(s.validKeys(), ", "))
}

func (s *SnmpV3AuthProtocolValue) Type() string {
	return "SnmpV3Protocol"
}

// validKeys returns a slice of valid keys for error messages
func (s *SnmpV3AuthProtocolValue) validKeys() []string {
	keys := make([]string, 0, len(validValuesSnmpV3AuthProtocol))
	for k := range validValuesSnmpV3AuthProtocol {
		keys = append(keys, k)
	}
	return keys
}
