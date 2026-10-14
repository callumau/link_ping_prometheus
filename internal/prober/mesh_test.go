package prober

import (
	"net/netip"
	"strings"
	"testing"
)

// pi-lens-ignore: go-test-functions
func TestFilterSelfTargets(t *testing.T) {
	targets := []Target{
		{Name: "syd", Address: "192.0.2.10:4000"},
		{Name: "fra", Address: "192.0.2.11:4000"},
		{Name: "lon", Address: "192.0.2.12:4000"},
	}

	got := FilterSelfTargets(targets, "fra")
	if len(got) != 2 || got[0].Name != "syd" || got[1].Name != "lon" {
		t.Fatalf("FilterSelfTargets did not drop fra while keeping order: %+v", got)
	}
	if len(targets) != 3 || targets[1].Name != "fra" {
		t.Error("the input slice must not be modified")
	}

	if all := FilterSelfTargets(targets, "nyc"); len(all) != 3 {
		t.Errorf("a non-matching source must keep every target, got %d", len(all))
	}
	// Target names are Prometheus label values: the match is exact, so a case
	// variant is a different series and must survive.
	if variant := FilterSelfTargets(targets, "SYD"); len(variant) != 3 {
		t.Errorf("the self match must be exact: got %d targets for a case variant", len(variant))
	}
	if empty := FilterSelfTargets(nil, "syd"); len(empty) != 0 {
		t.Errorf("nil input must yield an empty set, got %d", len(empty))
	}
}

// pi-lens-ignore: go-test-functions
func TestAllowEntriesFromTargets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []Target
		want    string
		wantErr string
	}{
		{
			name: "ip literals are joined in order",
			targets: []Target{
				{Name: "a", Address: "192.0.2.10:4000"},
				{Name: "b", Address: "198.51.100.11:4000"},
			},
			want: "192.0.2.10,198.51.100.11",
		},
		{
			name:    "an ipv6 literal loses its brackets",
			targets: []Target{{Name: "a", Address: "[2001:db8::1]:4000"}},
			want:    "2001:db8::1",
		},
		{
			name:    "a dns name cannot be allowlisted",
			targets: []Target{{Name: "a", Address: "peer.example.com:4000"}},
			wantErr: "not an IP literal",
		},
		{
			name:    "an fqdn root dot is still a name, not an IP",
			targets: []Target{{Name: "a", Address: "peer.example.com.:4000"}},
			wantErr: "not an IP literal",
		},
		{
			name:    "an ipv6 scope zone can never match a datagram source",
			targets: []Target{{Name: "a", Address: "[fe80::1%eth0]:4000"}},
			wantErr: "scope zone",
		},
		{
			name: "no targets yields an empty spec",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AllowEntriesFromTargets(tc.targets)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want an error containing %q, got spec %q / err %v", tc.wantErr, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("AllowEntriesFromTargets: %v", err)
			}
			if got != tc.want {
				t.Errorf("entries = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAllowEntriesFromTargetsComposeWithExplicitAllow pins the composition the
// CLI performs: the derived spec and -allow are joined and parsed once, so the
// allowlist rules (unmapping, size, dedup) apply to both sources exactly once.
// pi-lens-ignore: go-test-functions
func TestAllowEntriesFromTargetsComposeWithExplicitAllow(t *testing.T) {
	entries, err := AllowEntriesFromTargets([]Target{
		{Name: "a", Address: "192.0.2.10:4000"},
		{Name: "b", Address: "198.51.100.11:4000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	al, err := ParseAllowlist(entries + ",10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	for _, want := range []string{"192.0.2.10", "198.51.100.11", "10.2.3.4"} {
		addr, err := netip.ParseAddr(want)
		if err != nil {
			t.Fatal(err)
		}
		if !al.Contains(addr) {
			t.Errorf("allowlist must contain %s", want)
		}
	}
	if addr, err := netip.ParseAddr("203.0.113.9"); err != nil || al.Contains(addr) {
		t.Error("an address outside the derived peers and the explicit CIDR must be refused")
	}
}
