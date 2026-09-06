package prober_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestRunClient_ReloadAddsRemovesTargets: a reload applies file changes
// live — new targets start probing, removed targets stop (with inflight
// drained to zero, keeping the balance invariant) — and a broken file
// mid-edit keeps the previous set probing.
// pi-lens-ignore: go-test-functions
func TestRunClient_ReloadAddsRemovesTargets(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrA := udpEcho(t, ctx, func(buf []byte, w func([]byte)) { w(buf) })
	addrB := udpEcho(t, ctx, func(buf []byte, w func([]byte)) { w(buf) })

	// Initial targets file: A only. The reload content swaps to B.
	targetsFile := filepath.Join(t.TempDir(), "targets.json")
	writeTargets := func(names ...string) {
		var content string
		if len(names) == 0 {
			content = "[]"
		} else if len(names) == 1 {
			content = `[{"name":"` + names[0] + `","address":"` + addrB + `"}]`
		}
		if err := os.WriteFile(targetsFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeTargets() // empty file so the first reload introduces B

	hup := make(chan os.Signal, 1)
	cfg := prober.Config{
		Source:       testSource,
		Targets:      []prober.Target{{Name: "reload_a", Address: addrA}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  time.Second,
		TargetsPath:  targetsFile,
		ReloadSignal: hup,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// pi-lens-ignore: go-context-background-handler
		_ = prober.RunClient(ctx, cfg)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("RunClient did not stop after cancel")
		}
	}()

	waitFor := func(cond func() bool, what string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for: %s", what)
	}

	waitFor(func() bool { return getCounterValue(prober.ProbesSent, "reload_a", addrA) >= 3 }, "initial target probed")

	// Reload: A out, B in.
	writeTargets("reload_b")
	hup <- os.Interrupt
	waitFor(func() bool { return getCounterValue(prober.ProbesSent, "reload_b", addrB) >= 2 }, "new target probed after reload")

	// A must have stopped: sample its sent counter across a window and
	// require zero growth, and its inflight gauge must have drained.
	a1 := getCounterValue(prober.ProbesSent, "reload_a", addrA)
	time.Sleep(400 * time.Millisecond)
	a2 := getCounterValue(prober.ProbesSent, "reload_a", addrA)
	if a2 != a1 {
		t.Errorf("removed target must stop probing: sent %v -> %v in 400ms", a1, a2)
	}
	if n := getGaugeValue(prober.ProbesInflight, "reload_a", addrA); n != 0 {
		t.Errorf("removed target inflight must drain to 0 (balance invariant), got %v", n)
	}

	// A broken file mid-edit keeps the previous set running.
	if err := os.WriteFile(targetsFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	hup <- os.Interrupt
	time.Sleep(300 * time.Millisecond)
	b1 := getCounterValue(prober.ProbesSent, "reload_b", addrB)
	time.Sleep(400 * time.Millisecond)
	b2 := getCounterValue(prober.ProbesSent, "reload_b", addrB)
	if b2 <= b1 {
		t.Errorf("broken targets file must not stop the running set: sent %v -> %v", b1, b2)
	}

	// Reload back to A: B stops, A resumes.
	writeTargetsFile(t, targetsFile, "reload_c_a", addrA)
	hup <- os.Interrupt
	waitFor(func() bool { return getCounterValue(prober.ProbesSent, "reload_c_a", addrA) >= 2 }, "re-added target probed")
}

// writeTargetsFile writes a single-target file with a custom name.
func writeTargetsFile(t *testing.T, path, name, addr string) {
	t.Helper()
	content := `[{"name":"` + name + `","address":"` + addr + `"}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
