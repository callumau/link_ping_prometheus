package prober_test

import (
	"encoding/json"
	"os"
	"testing"

	"tcp_ping_prometheus/internal/prober"
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
