package prober

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestValidateTarget_IPishHosts pins the resolver-ambiguity guard: a
// target whose whole host field merely *looks* like an IP literal but that
// net.ParseIP rejects must not slip through the RFC 1123 label rules.
// Under a cgo/getaddrinfo resolver the legacy inet_aton semantics would
// then silently dial the wrong address (1.2.3.010 resolves as octal 8 →
// 1.2.3.8; 0x41 as hex → 0.0.0.65); under the pure-Go resolver the target
// would NXDOMAIN into a permanent dial-retry loop. Only whole-string
// IP-ish literals are tightened: a dotted name with labels, such as
// 10.0.0.1.example.com, stays a legal DNS name.
// pi-lens-ignore: go-test-functions
func TestValidateTarget_IPishHosts(t *testing.T) {
	cases := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"octal component rejected", "1.2.3.010:9100", true},
		{"leading-zero first component rejected", "01.2.3.4:9100", true},
		{"whole-string hex form rejected", "0x41:9100", true},
		{"dotted hex form rejected", "0x1.2.3.4:9100", true},
		{"out-of-range dotted quad rejected", "1.2.3.999:9100", true},
		{"bare integer host rejected (inet_aton integer form)", "42:9100", true},
		{"all-dots garbage rejected", "...:9100", true},
		{"valid IPv4 accepted", "1.2.3.4:9100", false},
		{"all-octets-zero IPv4 accepted", "0.0.0.0:9100", false},
		{"dotted DNS name with numeric labels accepted", "10.0.0.1.example.com:9100", false},
		{"plain DNS name accepted", "example.com:9100", false},
		{"single-label name starting with digits accepted", "1abc.example.com:9100", false},
		{"FQDN trailing dot accepted", "example.com.:9100", false},
		{"IPv6 literal accepted", "[::1]:9100", false},
		{"IPv6 link-local with zone accepted", "[fe80::1%eth0]:9100", false},
		// A zone's dot is for VLAN sub-interface names ("eth0.100"); a
		// dangling trailing dot inside the zone would dodge the IP-literal
		// check via the zone branch while the FQDN trailing-dot strip never
		// applies to IP literals — rejected at load time so the target
		// cannot strand in the dial-retry loop instead.
		{"IPv6 zone with dangling trailing dot rejected", "[fe80::1%eth0.]:9100", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTarget(tc.address)
			if got := err != nil; got != tc.wantErr {
				t.Errorf("ValidateTarget(%q) error = %v, wantErr %v", tc.address, err, tc.wantErr)
			}
		})
	}
}

// TestConfigValidate_MinProbeInterval pins the 1ms probe-interval floor.
// Below it the in-flight set grows to ~RTO/interval entries and every tick
// sweeps O(len(pending)) timeouts, pegging a core; the error must name the
// offending flag so the operator knows what to change.
// pi-lens-ignore: go-test-functions
func TestConfigValidate_MinProbeInterval(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
		errHas  string
	}{
		{
			"global below floor rejected",
			Config{Targets: []Target{{Name: "t", Address: "127.0.0.1:4000"}}, BaseInterval: 500 * time.Microsecond, BaseTimeout: time.Second},
			true, "-interval",
		},
		{
			"global exactly at floor accepted",
			Config{Targets: []Target{{Name: "t", Address: "127.0.0.1:4000"}}, BaseInterval: time.Millisecond, BaseTimeout: time.Second},
			false, "",
		},
		{
			"per-target below floor rejected",
			Config{Targets: []Target{{Name: "t", Address: "127.0.0.1:4000", Interval: 500 * time.Microsecond}}, BaseInterval: time.Second, BaseTimeout: time.Second},
			true, "interval",
		},
		{
			"per-target exactly at floor accepted",
			Config{Targets: []Target{{Name: "t", Address: "127.0.0.1:4000", Interval: time.Millisecond}}, BaseInterval: time.Second, BaseTimeout: time.Second},
			false, "",
		},
	}
	for _, tc := range cases {
		err := tc.cfg.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
			continue
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: expected nil, got %v", tc.name, err)
			continue
		}
		if tc.wantErr && tc.errHas != "" && !strings.Contains(err.Error(), tc.errHas) {
			t.Errorf("%s: error %q must name the offending flag %q", tc.name, err, tc.errHas)
		}
	}
}

// TestLoadTargets_MinProbeInterval pins the same floor on the targets.json
// path: LoadTargets re-validates through validateTargets, so a hot-reload
// with a sub-millisecond interval is rejected and keeps the previous set
// running instead of pegging a core.
func TestLoadTargets_MinProbeInterval(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"sub-ms interval rejected", `[{"name":"a","address":"127.0.0.1:4000","interval":"500us"}]`, true},
		{"1ms interval accepted", `[{"name":"a","address":"127.0.0.1:4000","interval":"1ms"}]`, false},
		{"omitted interval accepted", `[{"name":"a","address":"127.0.0.1:4000"}]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "targets-mininterval-*.json")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(f.Name())
			if _, err := f.WriteString(tc.body); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadTargets(f.Name()); (err != nil) != tc.wantErr {
				t.Errorf("LoadTargets error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestConfigValidate_PendingWindow: the pending set holds ~timeout/interval
// probes and every tick scans all of them, so an extreme ratio must be
// rejected at load time. minProbeInterval bounds the denominator; this pins
// the complementary bound on the numerator (and on per-target overrides,
// which used to be checked by nothing at all).
func TestConfigValidate_PendingWindow(t *testing.T) {
	tg := Target{Name: "t", Address: "127.0.0.1:4000"}
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
		errHas  string
	}{
		{"default window", Config{Targets: []Target{tg}, BaseInterval: 500 * time.Millisecond, BaseTimeout: time.Second}, false, ""},
		{"exactly at the cap", Config{Targets: []Target{tg}, BaseInterval: time.Millisecond, BaseTimeout: time.Second}, false, ""},
		{"one interval past the cap", Config{Targets: []Target{tg}, BaseInterval: time.Millisecond, BaseTimeout: time.Second + time.Millisecond}, true, "in-flight window"},
		{"a minute of timeout at 1ms interval", Config{Targets: []Target{tg}, BaseInterval: time.Millisecond, BaseTimeout: time.Minute}, true, "-timeout"},
		{"per-target override cannot open the hole", Config{
			Targets:      []Target{{Name: "t", Address: "127.0.0.1:4000", Interval: time.Millisecond, Timeout: time.Minute}},
			BaseInterval: time.Second, BaseTimeout: time.Second}, true, `target "t"`},
		{"per-target overrides inside the cap are fine", Config{
			Targets:      []Target{{Name: "t", Address: "127.0.0.1:4000", Interval: time.Millisecond, Timeout: 500 * time.Millisecond}},
			BaseInterval: time.Second, BaseTimeout: time.Second}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected the config to be rejected")
				}
				if tc.errHas != "" && !strings.Contains(err.Error(), tc.errHas) {
					t.Errorf("error %q must name the offending knob (%q)", err, tc.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}
