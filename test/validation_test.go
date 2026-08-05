package prober_test

import (
	"encoding/json"
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
		"a:1",
		"host:65535",
	}
	for _, addr := range valid {
		if err := prober.ValidateTarget(addr); err != nil {
			t.Errorf("expected %q to be valid, got %v", addr, err)
		}
	}

	invalid := []string{
		"",                // empty
		":80",             // no host
		"host:0",          // port too low
		"host:65536",      // port too high
		"host:abc",        // non-numeric port
		"host:",           // empty port
		"-bad.com:80",     // leading hyphen
		"bad-.com:80",     // trailing hyphen
		"bad_host.com:80", // underscore not valid in DNS
		string([]byte{'h', 0xC3, 's', 't'}) + ":80", // non-ASCII byte must not pass as a "letter"
	}
	for _, addr := range invalid {
		if err := prober.ValidateTarget(addr); err == nil {
			t.Errorf("expected %q to be invalid, got nil", addr)
		}
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
		err := tc.cfg.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: expected nil, got %v", tc.name, err)
		}
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
		err := cfg.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: expected nil, got %v", tc.name, err)
		}
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
