package prober

import (
	"os"
	"strings"
	"testing"
	"time"
)

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
