package prober

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ValidateTarget checks that address is a valid host:port string with a
// syntactically valid hostname or IP address and a port in [1, 65535].
// Validation is syntax-only: no DNS resolution happens here (load-time
// validation must not depend on the network).
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
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("target address %q has invalid port %q (must be 1-65535)", address, port)
	}
	if !isValidHost(host) {
		return fmt.Errorf("target address %q has invalid host", address)
	}
	return nil
}

// ValidateTargetName checks that name is usable as a Prometheus label
// value for the {target} dimension: non-empty, at most 63 characters,
// and free of control characters that would corrupt the exposition
// format or dashboards.
func ValidateTargetName(name string) error {
	if name == "" {
		return errors.New("target name is empty")
	}
	if len(name) > 63 {
		return fmt.Errorf("target name too long: %d chars (max 63)", len(name))
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("target name %q contains control character", name)
		}
	}
	return nil
}

// isValidHost checks whether host is a valid IP address or DNS name
// (RFC 1123 label rules — RFC 1035 as relaxed to allow labels starting
// with digits — max 253 characters, each label 1-63 characters, ASCII
// alphanumeric plus hyphen, no leading/trailing hyphen).
func isValidHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	// IPv6 literals arrive without brackets only if SplitHostPort stripped
	// them; net.ParseIP above already covers that. Anything else must be DNS.
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !isASCIILetterDigit(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

// isASCIILetterDigit reports whether c is in [a-zA-Z0-9]. Unlike
// unicode.IsLetter(rune(c)), it rejects bytes >= 0x80, so invalid
// UTF-8 and non-ASCII lookalikes cannot pass validation.
func isASCIILetterDigit(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
