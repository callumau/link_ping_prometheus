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
	// strconv.Atoi accepts a leading sign, so "+80" would otherwise pass
	// here and then fail at dial time with no load-time validation error;
	// require a plain ASCII-digit port. Leading zeros stay valid (they
	// dial to the same port).
	p, err := strconv.Atoi(port)
	if err != nil || !isDigits(port) || p < 1 || p > 65535 {
		return fmt.Errorf("target address %q has invalid port %q (must be 1-65535)", address, port)
	}
	if !isValidHost(host) {
		return fmt.Errorf("target address %q has invalid host", address)
	}
	return nil
}

// ValidateTargetName checks that name is usable as a Prometheus label
// value for the {target} dimension: non-empty, 1-63 chars, strict
// enterprise regex ^[a-zA-Z0-9_-]+$ (breaking for names with dots/spaces).
func ValidateTargetName(name string) error {
	if name == "" {
		return errors.New("target name is empty")
	}
	if len(name) > 63 {
		return fmt.Errorf("target name too long: %d chars (max 63)", len(name))
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return fmt.Errorf("target name %q contains invalid character %q (allowed: a-zA-Z0-9_-)", name, c)
		}
	}
	return nil
}

// isValidHost checks whether host is a valid IP address or DNS name
// (RFC 1123 label rules — RFC 1035 as relaxed to allow labels starting
// with digits — max 253 characters, each label 1-63 characters, ASCII
// alphanumeric plus hyphen, no leading/trailing hyphen). Two dialable
// forms go beyond the plain label rules: an IPv6 literal may carry a
// non-empty '%zone' scope suffix, and a DNS name may carry one trailing
// dot (the FQDN root, stripped by resolvers before lookup).
func isValidHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	// A zone literal ("fe80::1%eth0") is dialable, but net.ParseIP rejects
	// the '%zone' suffix. Accept it only on an otherwise valid IPv6
	// literal with a non-empty zone: an unmanaged '%' would otherwise
	// smuggle a non-dialable string past the label checks below.
	if i := strings.LastIndexByte(host, '%'); i > 0 {
		if z := host[i+1:]; validZone(z) {
			if a := net.ParseIP(host[:i]); a != nil && a.To4() == nil {
				return true
			}
		}
	}
	// Strip exactly one trailing dot: the label loop would reject the
	// empty final label of an FQDN ("host.example.com."), while a bare
	// "." or a "host.." still fails below.
	host = strings.TrimSuffix(host, ".")
	if len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
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

// isDigits reports whether s is a non-empty run of ASCII digits. Used
// for the port so a signed value cannot pass syntax validation and then
// fail only at dial time.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validZone reports whether zone is a plausible IPv6 scope identifier:
// non-empty and limited to ASCII alphanumerics, '_' and '-' (the
// character set of network interface names). Anything else is not a
// dialable zone and must not validate.
func validZone(zone string) bool {
	if zone == "" {
		return false
	}
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		if !isASCIILetterDigit(c) && c != '_' && c != '-' {
			return false
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
