package prober

import (
	"testing"
	"time"
)

// TestConfigValidate_DSCPRange pins the 0-63 bound end to end with the
// flag wiring. Untagged, unlike dscp_test.go's socket-marking test:
// DSCP validation is pure config parsing and must be covered on every
// platform (the marking itself is Linux-only, the bound is not).
// pi-lens-ignore: go-test-functions
func TestConfigValidate_DSCPRange(t *testing.T) {
	base := func() Config {
		return Config{
			Targets:      []Target{{Name: "t", Address: "127.0.0.1:4000"}},
			BaseInterval: 500 * time.Millisecond,
			BaseTimeout:  time.Second,
		}
	}
	for _, d := range []int{-1, 64, 255} {
		cfg := base()
		cfg.DSCP = d
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected error for dscp=%d", d)
		}
	}
	cfg := base()
	cfg.DSCP = 46
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected dscp=46 valid, got %v", err)
	}
}
