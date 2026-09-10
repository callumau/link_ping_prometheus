package prober_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

func TestLoadTargets(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "targets-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	targets := []prober.Target{
		{Name: "google", Address: "google.com:80"},
		{Name: "local", Address: "localhost:4000"},
	}
	data, _ := json.Marshal(targets)
	if _, err := tmpfile.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	loaded, err := prober.LoadTargets(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadTargets failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2 targets, got %d", len(loaded))
	}
	if loaded[0].Name != "google" {
		t.Errorf("expected first target name 'google', got %s", loaded[0].Name)
	}

	tmpfileInvalid, _ := os.CreateTemp("", "invalid-*.json")
	defer os.Remove(tmpfileInvalid.Name())
	tmpfileInvalid.Write([]byte("{invalid-json"))
	tmpfileInvalid.Close()

	_, err = prober.LoadTargets(tmpfileInvalid.Name())
	if err == nil {
		t.Error("expected error for invalid json, got nil")
	}

	_, err = prober.LoadTargets("non-existent-file.json")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestValidateTarget_PortAndHostRules(t *testing.T) {
	valid := []string{
		"127.0.0.1:4000",
		"[::1]:4000",
		"good-host.example.com:80",
		"good-host.example.com.:80", // FQDN root dot is dialable
		"[fe80::1%eth0]:5000",       // IPv6 zone literal is dialable
		"[fe80::1%eth0.100]:5000",   // dotted VLAN sub-interface zone is dialable
		"a:1",
		"host:65535",
		"host:+80", // Go's net port parser strips a leading '+' and dials it, so rejecting it would refuse a dialable address
	}
	for _, addr := range valid {
		if err := prober.ValidateTarget(addr); err != nil {
			t.Errorf("expected %q to be valid, got %v", addr, err)
		}
	}

	invalid := []string{
		"",                     // empty
		":80",                  // no host
		"host:0",               // port too low
		"host:65536",           // port too high
		"host:abc",             // non-numeric port
		"host:",                // empty port
		"host: 80",             // whitespace in the port
		"host:80 ",             // trailing whitespace in the port
		"-bad.com:80",          // leading hyphen
		"bad-.com:80",          // trailing hyphen
		"bad_host.com:80",      // underscore not valid in DNS
		"1.2.3.4.:80",          // IP literal with an FQDN root dot is not dialable
		"[fe80::1%]:5000",      // empty zone is not dialable
		"[fe80::1%eth 0]:5000", // junk in the zone
		"example.com%eth0:80",  // zone suffix on a DNS name
		"1.2.3.4%eth0:80",      // zone suffix on IPv4 (zones are IPv6-only)
		"host..example.com:80", // two dots is not an FQDN
		string([]byte{'h', 0xC3, 's', 't'}) + ":80", // non-ASCII byte must not pass as a "letter"
	}
	for _, addr := range invalid {
		if err := prober.ValidateTarget(addr); err == nil {
			t.Errorf("expected %q to be invalid, got nil", addr)
		}
	}
}

// assertValidate runs cfg.Validate and fails unless the outcome matches
// wantErr. Shared by the table-driven validation tests.
func assertValidate(t *testing.T, name string, cfg prober.Config, wantErr bool) {
	t.Helper()
	err := cfg.Validate()
	if wantErr && err == nil {
		t.Errorf("%s: expected error, got nil", name)
	}
	if !wantErr && err != nil {
		t.Errorf("%s: expected nil, got %v", name, err)
	}
}

func TestConfigValidate(t *testing.T) {
	tg := prober.Target{Name: "x", Address: "127.0.0.1:4000"}

	cases := []struct {
		name    string
		cfg     prober.Config
		wantErr bool
	}{
		{"valid", prober.Config{Targets: []prober.Target{tg}, BaseInterval: 500 * time.Millisecond, BaseTimeout: time.Second}, false},
		{"zero interval", prober.Config{Targets: []prober.Target{tg}, BaseInterval: 0, BaseTimeout: time.Second}, true},
		{"negative interval", prober.Config{Targets: []prober.Target{tg}, BaseInterval: -time.Second, BaseTimeout: time.Second}, true},
		{"zero timeout", prober.Config{Targets: []prober.Target{tg}, BaseInterval: time.Second, BaseTimeout: 0}, true},
		{"negative timeout", prober.Config{Targets: []prober.Target{tg}, BaseInterval: time.Second, BaseTimeout: -time.Second}, true},
		{"no targets", prober.Config{BaseInterval: time.Second, BaseTimeout: time.Second}, true},
		{"duplicate names", prober.Config{
			Targets: []prober.Target{
				{Name: "dup", Address: "127.0.0.1:4000"},
				{Name: "dup", Address: "127.0.0.1:4001"},
			},
			BaseInterval: time.Second, BaseTimeout: time.Second,
		}, true},
	}
	for _, tc := range cases {
		assertValidate(t, tc.name, tc.cfg, tc.wantErr)
	}
}

func TestValidateTargetName(t *testing.T) {
	valid := []string{"default", "google", "a", "name-with-dashes", "snake_case_ok"}
	for _, name := range valid {
		if err := prober.ValidateTargetName(name); err != nil {
			t.Errorf("expected %q to be valid, got %v", name, err)
		}
	}

	invalid := []string{
		"",
		"a\nb", // control character
		"a\x01b",
		"a\x7fb",
		string(make([]byte, 64)), // too long
	}
	for _, name := range invalid {
		if err := prober.ValidateTargetName(name); err == nil {
			t.Errorf("expected %q to be invalid, got nil", name)
		}
	}
}

func TestConfigValidate_RejectsBadNames(t *testing.T) {
	cases := []struct {
		name    string
		target  prober.Target
		wantErr bool
	}{
		{"empty name", prober.Target{Name: "", Address: "127.0.0.1:4000"}, true},
		{"control char", prober.Target{Name: "bad\nname", Address: "127.0.0.1:4000"}, true},
		{"too long", prober.Target{Name: string(make([]byte, 64)), Address: "127.0.0.1:4000"}, true},
		{"valid", prober.Target{Name: "ok", Address: "127.0.0.1:4000"}, false},
	}
	for _, tc := range cases {
		cfg := prober.Config{
			Targets:      []prober.Target{tc.target},
			BaseInterval: time.Second,
			BaseTimeout:  time.Second,
		}
		assertValidate(t, tc.name, cfg, tc.wantErr)
	}
}

// TestConfigValidate_PerTargetIntervalTimeout pins the per-target
// Interval/Timeout rules through Config.Validate: 0 means "inherit the
// global value" and is accepted; a positive override is accepted; a
// negative duration is rejected (it would flow into the probe schedule as
// an unusable period).
func TestConfigValidate_PerTargetIntervalTimeout(t *testing.T) {
	base := func(tg prober.Target) prober.Config {
		return prober.Config{Targets: []prober.Target{tg}, BaseInterval: time.Second, BaseTimeout: 2 * time.Second}
	}
	cases := []struct {
		name    string
		target  prober.Target
		wantErr bool
	}{
		{"zero interval and timeout inherit global", prober.Target{Name: "a", Address: "127.0.0.1:4000"}, false},
		{"positive overrides accepted", prober.Target{Name: "a", Address: "127.0.0.1:4000", Interval: 50 * time.Millisecond, Timeout: 200 * time.Millisecond}, false},
		{"negative interval rejected", prober.Target{Name: "a", Address: "127.0.0.1:4000", Interval: -time.Millisecond}, true},
		{"negative timeout rejected", prober.Target{Name: "a", Address: "127.0.0.1:4000", Timeout: -time.Millisecond}, true},
	}
	for _, tc := range cases {
		assertValidate(t, tc.name, base(tc.target), tc.wantErr)
	}
}

// TestLoadTargets_PerTargetIntervalTimeout pins the same rules on the
// targets.json path: LoadTargets re-validates through validateTargets, so a
// negative duration written in the file must be rejected at load time (a
// hot-reload keeps the previous set running) rather than slipping into a
// probe loop.
func TestLoadTargets_PerTargetIntervalTimeout(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"omitted inherits global", `[{"name":"a","address":"127.0.0.1:4000"}]`, false},
		{"explicit zero inherits global", `[{"name":"a","address":"127.0.0.1:4000","interval":"0s","timeout":"0s"}]`, false},
		{"positive overrides accepted", `[{"name":"a","address":"127.0.0.1:4000","interval":"50ms","timeout":"200ms"}]`, false},
		{"negative interval rejected", `[{"name":"a","address":"127.0.0.1:4000","interval":"-50ms"}]`, true},
		{"negative timeout rejected", `[{"name":"a","address":"127.0.0.1:4000","timeout":"-200ms"}]`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "targets-per-target-*.json")
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
			if _, err := prober.LoadTargets(f.Name()); (err != nil) != tc.wantErr {
				t.Errorf("LoadTargets error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadTargets_DuplicateNames(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "targets-dup-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	targets := []prober.Target{
		{Name: "same", Address: "127.0.0.1:4000"},
		{Name: "same", Address: "127.0.0.1:4001"},
	}
	data, _ := json.Marshal(targets)
	if _, err := tmpfile.Write(data); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	if _, err := prober.LoadTargets(tmpfile.Name()); err == nil {
		t.Error("expected error for duplicate target names, got nil")
	}
}

// TestServer_DynamicClientSeriesExpiresNoTraffic: the dedicated sweeper
// must age out an idle CIDR client even when no further probe arrives to
// trigger resolve()'s time-gated sweep. A single client that disappears
// would otherwise keep its series (and a frozen link_server_clock_skew
// alert) forever.
func TestServer_DynamicClientSeriesExpiresNoTraffic(t *testing.T) {
	prober.InitMetrics()
	oldTTL := prober.DynClientTTL
	prober.DynClientTTL = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() {
		cancel()
		<-done // join before restoring the shared var
		prober.DynClientTTL = oldTTL
	}()

	pc := listenUDP(t, ctx)
	allowed := mustAllow("127.0.0.0/8") // CIDR entry -> dynamic client path
	go func() {
		prober.ServePacketConn(ctx, pc, testSource, allowed, "")
		close(done)
	}()
	addr := pc.LocalAddr().String()

	c := dialFrom(t, addr, net.IPv4(127, 0, 0, 2))
	defer c.Close()
	if !echoOnce(t, c) {
		t.Fatal("CIDR client must be echoed")
	}
	for _, family := range []string{"link_server_probes_received_total", "link_server_clock_skew_seconds"} {
		if !serverSeriesExists(t, family, map[string]string{"source": testSource, "client": "127.0.0.2"}) {
			t.Fatalf("%s series must exist for the admitted dynamic client", family)
		}
	}

	// No further traffic from any client: wait past DynClientTTL plus the
	// sweeper's first tick, then assert the idle client's series is gone.
	time.Sleep(1400 * time.Millisecond)
	for _, family := range []string{"link_server_probes_received_total", "link_server_clock_skew_seconds"} {
		if serverSeriesExists(t, family, map[string]string{"source": testSource, "client": "127.0.0.2"}) {
			t.Errorf("%s series must be deleted once the client is idle past DynClientTTL with no further traffic", family)
		}
	}
}
