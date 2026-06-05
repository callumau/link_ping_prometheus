package prober

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"
)

// ValidateTarget checks that address is a valid host:port string with
// a resolvable hostname or IP address.
func ValidateTarget(address string) error {
	if address == "" {
		return errors.New("target address is empty")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", address, err)
	}
	if host == "" {
		return fmt.Errorf("target address %q has no host", address)
	}
	_ = port
	if !isValidHost(host) {
		return fmt.Errorf("target address %q has invalid host", address)
	}
	return nil
}

// isValidHost checks whether host is a valid IP address or DNS name
// (RFC 1035 label rules, max 253 characters, each label 1–63 characters,
// alphanumeric plus hyphen).
func isValidHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range []byte(label) {
			if !unicode.IsLetter(rune(c)) && !unicode.IsNumber(rune(c)) && c != '-' {
				return false
			}
		}
	}
	return true
}
