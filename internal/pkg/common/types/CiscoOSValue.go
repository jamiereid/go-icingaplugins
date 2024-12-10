package types

import (
	"errors"
	"strings"
)

type CiscoOS uint8

const (
	CiscoOSIOS CiscoOS = iota
	CiscoOSNXOS
)

// MemoryMibValue is a custom flag type for MemoryMib
type CiscoOSValue struct {
	Value CiscoOS
}

var validValuesCiscoOS = map[string]CiscoOS{
	"ios":  CiscoOSIOS,
	"nxos": CiscoOSNXOS,
}

func (s *CiscoOSValue) String() string {
	for it_index, it := range validValuesCiscoOS {
		if it == s.Value {
			return it_index
		}
	}
	return ""
}

// Set parses and sets the value from a string
func (s *CiscoOSValue) Set(value string) error {
	if flag, ok := validValuesCiscoOS[strings.ToLower(value)]; ok {
		s.Value = flag
		return nil
	}
	return errors.New("invalid value for MemoryMibValue, valid options are: " +
		strings.Join(s.validKeys(), ", "))
}

func (s *CiscoOSValue) Type() string {
	return "CiscoOS"
}

// validKeys returns a slice of valid keys for error messages
func (s *CiscoOSValue) validKeys() []string {
	keys := make([]string, 0, len(validValuesCiscoOS))
	for it_index := range validValuesCiscoOS {
		keys = append(keys, it_index)
	}
	return keys
}
