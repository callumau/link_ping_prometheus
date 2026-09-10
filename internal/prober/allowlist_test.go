package prober

import (
	"fmt"
	"testing"
)

// TestParseAllowlist_ErrorPaths covers every reject path of the fail-closed
// allowlist parser. Two of them would otherwise fail CLOSED SILENTLY, which is
// the dangerous direction for a security control: a 4-in-6 prefix shorter than
// /96 and a zoned IPv6 literal both parse but can never match a datagram
// source, so accepting them leaves the server running normally while dropping
// 100% of that client's probes as allowlist drops. The size cap matters for
// the same reason in reverse — an unbounded list is a per-packet scan.
func TestParseAllowlist_ErrorPaths(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
		wantN   int
	}{
		{"empty list parses to admit-nothing", "", false, 0},
		{"blank entries are skipped", " , , ", false, 0},
		{"plain IPv4 exact", "203.0.113.5", false, 1},
		{"IPv4 CIDR", "203.0.113.0/24", false, 1},
		{"IPv6 exact", "2001:db8::1", false, 1},
		{"IPv6 CIDR", "2001:db8::/32", false, 1},
		{"4-in-6 exact is normalised", "::ffff:10.0.0.1", false, 1},
		{"4-in-6 /104 prefix is normalised", "::ffff:10.0.0.0/104", false, 1},
		{"mixed list", "10.0.0.1, 10.0.0.0/8", false, 2},
		{"garbage is rejected", "not-an-ip", true, 0},
		{"host:port is rejected", "10.0.0.1:4000", true, 0},
		{"a bare CIDR length is rejected", "10.0.0.1/", true, 0},
		{"a prefix longer than the address is rejected", "10.0.0.0/33", true, 0},
		{"4-in-6 prefix shorter than /96 would never match", "::ffff:0:0/16", true, 0},
		{"a zone can never match a datagram source", "fe80::1%eth0", true, 0},
		{"a zone on a 4-in-6 literal is rejected too", "::ffff:10.0.0.1%eth0", true, 0},
		{"a malformed entry rejects the whole list", "10.0.0.1,oops,10.0.0.2", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			al, err := ParseAllowlist(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseAllowlist(%q) must be rejected, got %d entries", tc.in, al.Len())
				}
				if al != nil {
					t.Errorf("a rejected allowlist must be nil, got %v", al)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAllowlist(%q): %v", tc.in, err)
			}
			if al.Len() != tc.wantN {
				t.Errorf("ParseAllowlist(%q).Len() = %d, want %d", tc.in, al.Len(), tc.wantN)
			}
		})
	}
}

// TestParseAllowlist_SizeCap: the entry cap bounds the exact-IP handle map and
// the per-datagram prefix scan; 256 entries pass, 257 fail.
func TestParseAllowlist_SizeCap(t *testing.T) {
	build := func(n int) string {
		in := ""
		for i := range n {
			if i > 0 {
				in += ","
			}
			in += fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		}
		return in
	}
	if al, err := ParseAllowlist(build(256)); err != nil || al.Len() != 256 {
		t.Fatalf("256 entries must be accepted (len=%d, err=%v)", al.Len(), err)
	}
	if _, err := ParseAllowlist(build(257)); err == nil {
		t.Error("257 entries must be rejected: the cap bounds the exact-IP handle map")
	}
}
