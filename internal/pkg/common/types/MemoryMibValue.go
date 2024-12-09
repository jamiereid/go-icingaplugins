package types

import (
	"errors"
	"strings"
)

type MemoryMib uint8

const (
	MemoryMibCiscoProcessMib MemoryMib = iota
	MemoryMibCiscoMemoryPoolMib
)

// MemoryMibValue is a custom flag type for MemoryMib
type MemoryMibValue struct {
	Value MemoryMib
}

var validValuesMemoryMib = map[string]MemoryMib{
	"cisco-process-mib":     MemoryMibCiscoProcessMib,
	"cisco-memory-pool-mib": MemoryMibCiscoMemoryPoolMib,
}

func (s *MemoryMibValue) String() string {
	for k, v := range validValuesMemoryMib {
		if v == s.Value {
			return k
		}
	}
	return ""
}

// Set parses and sets the value from a string
func (s *MemoryMibValue) Set(value string) error {
	if flag, ok := validValuesMemoryMib[strings.ToLower(value)]; ok {
		s.Value = flag
		return nil
	}
	return errors.New("invalid value for MemoryMibValue, valid options are: " +
		strings.Join(s.validKeys(), ", "))
}

func (s *MemoryMibValue) Type() string {
	return "MemoryMib"
}

// validKeys returns a slice of valid keys for error messages
func (s *MemoryMibValue) validKeys() []string {
	keys := make([]string, 0, len(validValuesMemoryMib))
	for k := range validValuesMemoryMib {
		keys = append(keys, k)
	}
	return keys
}
