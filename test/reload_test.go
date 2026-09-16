package prober_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"link_ping_prometheus/internal/prober"
)

// TestRunClient_ReloadAddsRemovesTargets: a reload applies file changes
// live — new targets start probing, removed targets stop and have their
// metric series DELETED (Prometheus staleness; see deleteTargetSeries) and
// are dropped from /status, a merely-CHANGED target keeps its series and
// keeps probing, and a broken file mid-edit keeps the previous set probing.
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

	reg := prober.NewStatusRegistry()
	hup := make(chan os.Signal, 1)
	cfg := prober.Config{
		Source:       testSource,
		Targets:      []prober.Target{{Name: "reload_a", Address: addrA}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  time.Second,
		TargetsPath:  targetsFile,
		ReloadSignal: hup,
		Status:       reg,
	}

	runClientAsync(t, ctx, cancel, cfg)
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

	// Positive control for the /status ghost check below: without this, a
	// regression that stops Status.Update entirely would make the "absent"
	// assertion pass vacuously.
	if !snapshotHasTarget(reg, "reload_a") {
		t.Fatal("precondition: reload_a must be present in the /status snapshot while it is running")
	}

	// Reload: A out, B in.
	writeTargets("reload_b")
	hup <- os.Interrupt
	waitFor(func() bool { return getCounterValue(prober.ProbesSent, "reload_b", addrB) >= 2 }, "new target probed after reload")

	// A REMOVED target's series must be DELETED from the registry, not left
	// at its last value: Prometheus staleness only kicks in once a series
	// disappears from a scrape, so a still-registered series freezes at its
	// last value (e.g. link_up=1 forever on a decommissioned endpoint). This
	// MUST be checked without touching the vec: getCounterValue/
	// getGaugeValue resolve via WithLabelValues, which re-creates a deleted
	// series as 0 and makes the "is it gone?" assertion impossible to fail.
	for _, family := range []string{"link_probes_sent_total", "link_up", "link_rtt_seconds", "link_probes_inflight"} {
		if metricSeriesExists(t, family, testSource, "reload_a", addrA) {
			t.Errorf("removed target's %s series is still registered — deletion (Prometheus staleness) is broken", family)
		}
	}
	// It must also be gone from /status, or a removed target lingers as a
	// ghost row.
	for _, s := range reg.Snapshot() {
		if s.Name == "reload_a" {
			t.Errorf("removed target still present in /status snapshot: %+v", s)
		}
	}

	// A CHANGED target (same name, new per-target interval) is still the
	// same monitored endpoint: its series must survive the loop restart and
	// its counters must keep growing. apply() must purge a target only when
	// it was removed from the file, never when it merely changed.
	if !metricSeriesExists(t, "link_probes_sent_total", testSource, "reload_b", addrB) {
		t.Fatal("reload_b series must exist before the change reload")
	}
	sentBefore := getCounterValue(prober.ProbesSent, "reload_b", addrB)
	writeTargetsInterval(t, targetsFile, "reload_b", addrB, "100ms")
	hup <- os.Interrupt
	waitFor(func() bool { return getCounterValue(prober.ProbesSent, "reload_b", addrB) > sentBefore+2 }, "changed target keeps probing")
	if !metricSeriesExists(t, "link_probes_sent_total", testSource, "reload_b", addrB) {
		t.Errorf("a CHANGED target (same name, new interval) must keep its metric series, but it was deleted")
	}

	// An ADDRESS change (same name) is a DIFFERENT endpoint: the old address's
	// series must be withdrawn too, or a retired IP keeps exporting its last
	// link_up=1 for the life of the process — the same frozen-green bug via
	// the common "edit the target's IP in targets.json" path. The new address
	// gets its own series.
	addrB2 := udpEcho(t, ctx, func(buf []byte, w func([]byte)) { w(buf) })
	writeTargetsFile(t, targetsFile, "reload_b", addrB2)
	hup <- os.Interrupt
	waitFor(func() bool { return getCounterValue(prober.ProbesSent, "reload_b", addrB2) >= 2 }, "target probed at its new address")
	if metricSeriesExists(t, "link_probes_sent_total", testSource, "reload_b", addrB) {
		t.Errorf("an address change must withdraw the OLD address's series, but it is still registered")
	}
	if !metricSeriesExists(t, "link_probes_sent_total", testSource, "reload_b", addrB2) {
		t.Errorf("the new address must have its own series")
	}

	// A broken file mid-edit keeps the previous set running.
	if err := os.WriteFile(targetsFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	hup <- os.Interrupt
	time.Sleep(300 * time.Millisecond)
	b1 := getCounterValue(prober.ProbesSent, "reload_b", addrB2)
	time.Sleep(400 * time.Millisecond)
	b2 := getCounterValue(prober.ProbesSent, "reload_b", addrB2)
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

// snapshotHasTarget reports whether a target name is currently present in
// the /status registry, so "absent" assertions can have a live positive
// control instead of passing against an empty registry.
func snapshotHasTarget(reg *prober.StatusRegistry, name string) bool {
	for _, s := range reg.Snapshot() {
		if s.Name == name {
			return true
		}
	}
	return false
}

// writeTargetsInterval writes a single-target file with an explicit
// per-target interval — the change-detection key apply() compares to decide
// whether a target merely changed (keep series) or was removed (purge).
func writeTargetsInterval(t *testing.T, path, name, addr, interval string) {
	t.Helper()
	content := `[{"name":"` + name + `","address":"` + addr + `","interval":"` + interval + `"}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// metricSeriesExists reports whether the named metric family currently has a
// series with exactly {source,target,address}. It uses Gather(), which only
// reflects series already registered — unlike WithLabelValues, which CREATES a
// zero-valued series on read and would make a "series was deleted" assertion
// impossible to fail.
func metricSeriesExists(t *testing.T, family, source, target, address string) bool {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	want := map[string]string{"source": source, "target": target, "address": address}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			got := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			if len(got) != len(want) {
				continue
			}
			match := true
			for k, v := range want {
				if got[k] != v {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// TestBalanceHoldsAcrossKeptSeriesRestart pins the audit finding
// client.reload-restart-cancel-abandon-unaccounted: a reload that changes
// only a target's per-target interval keeps the series and restarts the
// loop, and the old loop's clean-cancel exit must preserve the documented
// balance sent == rtt_count + timed_out + inflight (+ corrupted) on the
// still-exported series. The shutdown path keeps inflight-only accounting
// (series stop being exported; pinned by
// TestGracefulShutdown_NoPhantomTimeouts) — this test asserts only while
// the replacement loop is running.
//
// The listener is a discard socket: writes succeed, nothing echoes, so
// every probe resolves as a timeout and rtt_count/corrupted stay 0.
func TestBalanceHoldsAcrossKeptSeriesRestart(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Discard listener: binds, never reads — writes succeed, no echoes.
	discard := listenUDP(t, ctx)
	addr := discard.LocalAddr().String()
	target := "bal_restart"

	targetsFile := filepath.Join(t.TempDir(), "targets.json")
	writeTargetsFile(t, targetsFile, target, addr)

	reg := prober.NewStatusRegistry()
	hup := make(chan os.Signal, 1)
	cfg := prober.Config{
		Source:       testSource,
		Targets:      []prober.Target{{Name: target, Address: addr}},
		BaseInterval: 10 * time.Millisecond,
		BaseTimeout:  300 * time.Millisecond,
		TargetsPath:  targetsFile,
		ReloadSignal: hup,
		Status:       reg,
	}
	runClientAsync(t, ctx, cancel, cfg)

	// Balance read through Gather(): reflects only series already
	// registered, so it cannot manufacture a zero-valued series the way
	// WithLabelValues would (this target is never purged, but the balance
	// must be asserted on exactly the series the scraper would see).
	balance := func() (drift float64, sent float64) {
		fams, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatalf("gather metrics: %v", err)
		}
		want := map[string]string{"source": testSource, "target": target, "address": addr}
		values := map[string]float64{}
		read := func(name string, pick func(*dto.Metric) float64) {
			for _, f := range fams {
				if f.GetName() != name {
					continue
				}
				for _, m := range f.GetMetric() {
					got := make(map[string]string, len(m.GetLabel()))
					for _, lp := range m.GetLabel() {
						got[lp.GetName()] = lp.GetValue()
					}
					if len(got) != len(want) {
						continue
					}
					match := true
					for k, v := range want {
						if got[k] != v {
							match = false
							break
						}
					}
					if match {
						values[name] = pick(m)
					}
				}
			}
		}
		read("link_probes_sent_total", func(m *dto.Metric) float64 { return m.GetCounter().GetValue() })
		read("link_rtt_seconds_count", func(m *dto.Metric) float64 { return float64(m.GetHistogram().GetSampleCount()) })
		read("link_probes_timed_out_total", func(m *dto.Metric) float64 { return m.GetCounter().GetValue() })
		read("link_probes_corrupted_total", func(m *dto.Metric) float64 { return m.GetCounter().GetValue() })
		read("link_probes_inflight", func(m *dto.Metric) float64 { return m.GetGauge().GetValue() })
		sent = values["link_probes_sent_total"]
		drift = sent - values["link_rtt_seconds_count"] - values["link_probes_timed_out_total"] - values["link_probes_corrupted_total"] - values["link_probes_inflight"]
		return drift, sent
	}

	// Settle at 10ms interval: sent >= 40 needs 400ms, timed_out >= 15
	// needs ~300ms + one interval of sweep latency. A generous wait with
	// the same skip guard the accuracy tests use keeps the test honest
	// under CPU load.
	deadline := time.Now().Add(5 * time.Second)
	for {
		sent := getCounterValue(prober.ProbesSent, target, addr)
		timedOut := getCounterValue(prober.ProbesTimedOut, target, addr)
		if sent >= 40 && timedOut >= 15 {
			break
		}
		if time.Now().After(deadline) {
			skipIfRTTNearTimeout(t, target, addr, cfg.BaseTimeout)
			t.Fatalf("probes did not settle: sent=%f timed_out=%f", sent, timedOut)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if drift, sent := balance(); drift != 0 {
		t.Fatalf("pre-restart control: balance drift = %f (sent=%f); the restart path must not be the only balance-preserving path", drift, sent)
	}

	// Keep-restart: the address is unchanged, only the interval changes —
	// the apply() keep branch runs (series stay attached, sent continues).
	writeTargetsInterval(t, targetsFile, target, addr, "100ms")
	hup <- syscall.SIGTERM

	// Confirm the restart took effect, then assert the balance EXACTLY while
	// the replacement loop is still running (no shutdown contamination). At
	// 100ms the replacement needs ~1.5s for 15 probes; the pre-restart
	// counters are snapshotted once and the wait requires that many NEW
	// resolved probes so the assertion sees post-restart accounting, not
	// just the pre-restart state.
	preSent := getCounterValue(prober.ProbesSent, target, addr)
	restartWait := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(restartWait) {
			skipIfRTTNearTimeout(t, target, addr, cfg.BaseTimeout)
			t.Fatalf("restart did not produce enough post-restart probes: sent=%f (pre=%f)", getCounterValue(prober.ProbesSent, target, addr), preSent)
		}
		time.Sleep(50 * time.Millisecond)
		if getCounterValue(prober.ProbesSent, target, addr)-preSent >= 15 {
			break
		}
	}
	if drift, sent := balance(); drift != 0 {
		t.Fatalf("kept-series restart broke the balance: drift=%f (sent=%f) — the clean-cancel exit of the old loop must count abandoned probes as timed out when the series stays exported", drift, sent)
	}
}
func TestReload_EmptyArrayStopsProbingAndPurges(t *testing.T) {
	prober.InitMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// AGENTS.md: "a reload whose file parses to an empty array logs a
	// warning that all probing has stopped" — the warning is the operator's
	// only signal that a save-as-[] mistake silenced every link at once, so
	// it is asserted here alongside the behavioral consequences. The
	// capture must be installed before RunClient launches (the reload
	// happens in the client goroutine).
	capture := &logCapture{}
	old := slog.Default()
	slog.SetDefault(slog.New(capture))
	defer slog.SetDefault(old)

	var received atomic.Int64
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		received.Add(1)
		w(buf)
	})

	targetsFile := filepath.Join(t.TempDir(), "targets.json")
	writeJSON := func(content string) {
		t.Helper()
		if err := os.WriteFile(targetsFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(`[{"name":"empty_reload","address":"` + addr + `"}]`)

	reg := prober.NewStatusRegistry()
	hup := make(chan os.Signal, 1)
	cfg := prober.Config{
		Source:       testSource,
		Targets:      []prober.Target{{Name: "empty_reload", Address: addr}},
		BaseInterval: 50 * time.Millisecond,
		BaseTimeout:  time.Second,
		TargetsPath:  targetsFile,
		ReloadSignal: hup,
		Status:       reg,
	}
	runClientAsync(t, ctx, cancel, cfg)

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
	waitFor(func() bool { return received.Load() >= 3 }, "initial probes on the wire")

	writeJSON("[]")
	hup <- os.Interrupt
	waitFor(func() bool {
		return !metricSeriesExists(t, "link_probes_sent_total", testSource, "empty_reload", addr)
	}, "series purged by the empty-array reload")

	// Non-vacuous stop check: nothing may reach the echo server afterwards.
	after := received.Load()
	time.Sleep(300 * time.Millisecond)
	if n := received.Load(); n != after {
		t.Errorf("empty-array reload must stop all probing: %d frames arrived after the purge", n-after)
	}
	for _, s := range reg.Snapshot() {
		if s.Name == "empty_reload" {
			t.Errorf("empty-array reload must drop the target from /status, still present: %+v", s)
		}
	}
	if got := capture.count("ALL probing stopped"); got != 1 {
		t.Errorf("empty-array reload must warn exactly once that all probing stopped, got %d", got)
	}
}
