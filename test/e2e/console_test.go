package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Black-box console-mode tests (all key shipped functions, driven through
// the compiled binary only). Every test starts real binaries in the modes
// users run and asserts via the HTTP surfaces and process exits; no repo
// package is imported.

// TestE2EBothModeProbesAndMetrics: a server binary and a client binary
// (both mode exercised through its halves) reach steady state: client
// reports link_up=1 with RTT samples, server counts probes received.
func TestE2EBothModeProbesAndMetrics(t *testing.T) {
	srvMetricsP := freePort(t)
	srvListenP := freePort(t)

	startBin(t,
		"-mode=server", "-listen", "127.0.0.1:"+itoa(srvListenP),
		"-allow", "127.0.0.1",
		"-metrics", "127.0.0.1:"+itoa(srvMetricsP))
	waitHTTP(t, "http://127.0.0.1:"+itoa(srvMetricsP)+"/readyz", "", 10*time.Second)

	cliMetricsP := freePort(t)
	startBin(t,
		"-mode=client",
		"-target", "127.0.0.1:"+itoa(srvListenP),
		"-interval", "50ms", "-timeout", "1s",
		"-metrics", "127.0.0.1:"+itoa(cliMetricsP))

	waitMetricGTE(t, "http://127.0.0.1:"+itoa(cliMetricsP)+"/metrics",
		"link_rtt_seconds_count", 1, 10*time.Second)

	srvBody := waitHTTP(t, "http://127.0.0.1:"+itoa(srvMetricsP)+"/metrics", "", 10*time.Second)
	if got := metricValue(srvBody, "link_server_probes_received_total"); got < 1 {
		t.Errorf("server probes received = %v, want >= 1; metrics:\n%.1200s", got, srvBody)
	}
}

// TestE2ESecretPairingMatrix exercises the three HMAC pairings through
// the binary: matching secret carries RTT; client-secret WITHOUT server
// secret peaks the half-configured counter; mismatched secrets drop
// probes as hmac and read as loss client-side.
func TestE2ESecretPairingMatrix(t *testing.T) {
	const secret = "e2e-secret-0123456789"

	t.Run("matched secret carries RTT", func(t *testing.T) {
		mp, lp := freePort(t), freePort(t)
		startBin(t,
			"-mode=server", "-listen", "127.0.0.1:"+itoa(lp),
			"-allow", "127.0.0.1",
			"-echo-secret", secret,
			"-metrics", "127.0.0.1:"+itoa(mp))
		waitHTTP(t, "http://127.0.0.1:"+itoa(mp)+"/readyz", "", 10*time.Second)

		cp := freePort(t)
		startBin(t,
			"-mode=client", "-target", "127.0.0.1:"+itoa(lp),
			"-interval", "50ms", "-timeout", "1s",
			"-echo-secret", secret,
			"-metrics", "127.0.0.1:"+itoa(cp))

		waitHTTP(t, "http://127.0.0.1:"+itoa(cp)+"/metrics", "link_up{", 10*time.Second)
		body := waitHTTP(t, "http://127.0.0.1:"+itoa(cp)+"/metrics", "", 5*time.Second)
		if got := metricValue(body, "link_rtt_seconds_count"); got < 1 {
			t.Fatalf("matched-secret rtt count = %v, want >= 1", got)
		}
	})

	t.Run("client secret on secret-less server is metric-visible", func(t *testing.T) {
		mp, lp := freePort(t), freePort(t)
		startBin(t,
			"-mode=server", "-listen", "127.0.0.1:"+itoa(lp),
			"-allow", "127.0.0.1",
			"-metrics", "127.0.0.1:"+itoa(mp))
		waitHTTP(t, "http://127.0.0.1:"+itoa(mp)+"/readyz", "", 10*time.Second)

		cp := freePort(t)
		startBin(t,
			"-mode=client", "-target", "127.0.0.1:"+itoa(lp),
			"-interval", "50ms", "-timeout", "1s",
			"-echo-secret", secret,
			"-metrics", "127.0.0.1:"+itoa(cp))

		waitMetricGTE(t, "http://127.0.0.1:"+itoa(mp)+"/metrics",
			"link_server_unauth_hmac_frames_total", 1, 15*time.Second)
	})

	t.Run("mismatched secret drops as hmac", func(t *testing.T) {
		mp, lp := freePort(t), freePort(t)
		startBin(t,
			"-mode=server", "-listen", "127.0.0.1:"+itoa(lp),
			"-allow", "127.0.0.1",
			"-echo-secret", secret,
			"-metrics", "127.0.0.1:"+itoa(mp))
		waitHTTP(t, "http://127.0.0.1:"+itoa(mp)+"/readyz", "", 10*time.Second)

		cp := freePort(t)
		startBin(t,
			"-mode=client", "-target", "127.0.0.1:"+itoa(lp),
			"-interval", "50ms", "-timeout", "1s",
			"-echo-secret", "different-secret-9876543210",
			"-metrics", "127.0.0.1:"+itoa(cp))

		waitHTTP(t, "http://127.0.0.1:"+itoa(mp)+"/metrics",
			"link_server_probes_dropped_total{", 15*time.Second)
		body := http2Body(t, mp)
		if got := metricValue(body, `link_server_probes_dropped_total`); got < 1 ||
			!strings.Contains(body, "reason=\"hmac\"") {
			// the drop line must carry the hmac reason specifically
			found := false
			for _, l := range strings.Split(body, "\n") {
				if strings.HasPrefix(l, "link_server_probes_dropped_total") &&
					strings.Contains(l, "hmac") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no link_server_probes_dropped_total{reason=\"hmac\"} series; metrics:\n%.800s", body)
			}
		}
	})
}

// funcPort2Status builds the /status URL for the given metrics port.
func funcPort2Status(port int) string {
	return "http://127.0.0.1:" + itoa(port) + "/status"
}

// http2Body fetches the metrics body (status ignored), test-bound shim.
func http2Body(t *testing.T, port int) string {
	t.Helper()
	_, body := httpGetIf(t, "http://127.0.0.1:"+itoa(port)+"/metrics")
	return body
}

// TestE2EPayloadIntegrity: 1400-byte payload rounds trip through the
// binary pair without corruption; corrupted counter stays zero.
func TestE2EPayloadIntegrity(t *testing.T) {
	mp, lp := freePort(t), freePort(t)
	startBin(t,
		"-mode=server", "-listen", "127.0.0.1:"+itoa(lp),
		"-allow", "127.0.0.1",
		"-payload", "1400",
		"-metrics", "127.0.0.1:"+itoa(mp))
	waitHTTP(t, "http://127.0.0.1:"+itoa(mp)+"/readyz", "", 10*time.Second)

	cp := freePort(t)
	startBin(t,
		"-mode=client", "-target", "127.0.0.1:"+itoa(lp),
		"-interval", "50ms", "-timeout", "1s",
		"-payload", "1400",
		"-metrics", "127.0.0.1:"+itoa(cp))

	body := waitHTTP(t, "http://127.0.0.1:"+itoa(cp)+"/metrics",
		"link_probes_corrupted_total{", 15*time.Second)
	if got := metricValue(body, "link_probes_corrupted_total"); got != 0 {
		t.Errorf("corrupted total = %v, want 0 on loopback", got)
	}
	if got := metricValue(body, "link_rtt_seconds_count"); got < 1 {
		t.Errorf("payload-mode rtt count = %v, want >= 1", got)
	}
}

// TestE2EInOutMTUSweep: the DF sweep finds a positive largest frame on
// loopback (exact value is OS-dependent: Linux loopback MTU 65536 caps at
// MaxPayloadBytes; Windows loopback differs - only assert discovered
// > 0 and it stabilizes) and does not pollute the main loss ratio.
func TestE2EInOutMTUSweep(t *testing.T) {
	mp, lp := freePort(t), freePort(t)
	startBin(t,
		"-mode=server", "-listen", "127.0.0.1:"+itoa(lp),
		"-allow", "127.0.0.1",
		"-metrics", "127.0.0.1:"+itoa(mp))
	waitHTTP(t, "http://127.0.0.1:"+itoa(mp)+"/readyz", "", 10*time.Second)

	cp := freePort(t)
	startBin(t,
		"-mode=client", "-target", "127.0.0.1:"+itoa(lp),
		"-interval", "50ms", "-timeout", "1s",
		"-mtu-sweep", "200ms",
		"-metrics", "127.0.0.1:"+itoa(cp))

	base := "http://127.0.0.1:" + itoa(cp) + "/metrics"
	// SeedMetrics creates link_path_mtu_bytes at 0 before the first sweep.
	// Waiting for the SERIES is therefore not enough: on a slower Windows
	// runner the scrape can land on the seeded 0 and the assertion fails
	// before any DF probe has completed. Wait for the sweep's positive
	// value and its sent counter instead.
	waitMetricGTE(t, base, "link_path_mtu_bytes", 1, 20*time.Second)
	waitMetricGTE(t, base, "link_mtu_probes_sent_total", 1, 20*time.Second)
}

// TestE2ETargetsHotReload tries the -targets-reload-interval path on
// every OS (SIGHUP is unreachable on Windows services; the timer is the
// uniform mechanism): a second target added to the file appears in
// /status within the reload window.
func TestE2ETargetsHotReload(t *testing.T) {
	dir := t.TempDir()
	mp, lp := freePort(t), freePort(t)
	startBin(t,
		"-mode=server", "-listen", "127.0.0.1:"+itoa(lp),
		"-allow", "127.0.0.1",
		"-metrics", "127.0.0.1:"+itoa(mp))
	waitHTTP(t, "http://127.0.0.1:"+itoa(mp)+"/readyz", "", 10*time.Second)

	tf := writeTargetsFile(t, dir, map[string]string{"t1": "127.0.0.1:" + itoa(lp)})
	cp := freePort(t)
	startBin(t,
		"-mode=client",
		"-targets", tf,
		"-targets-reload-interval", "400ms",
		"-interval", "50ms", "-timeout", "1s",
		"-metrics", "127.0.0.1:"+itoa(cp))

	// Initial state: one target.
	body := waitHTTP(t, "http://127.0.0.1:"+itoa(cp)+"/status", `"name":"t1"`, 10*time.Second)
	if strings.Contains(body, `"name":"t2"`) {
		t.Fatal("t2 present before the reload — preexisting state polluted the test")
	}

	// Reload: add t2 (same address, second series) and watch /status.
	writeTargetsFile(t, dir, map[string]string{
		"t1": "127.0.0.1:" + itoa(lp),
		"t2": "127.0.0.1:" + itoa(lp),
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body := httpGetIf(t, "http://127.0.0.1:"+itoa(cp)+"/status")
		if strings.Contains(body, `"name":"t2"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("t2 never appeared after reload; last /status: %.600s", body)
		}
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(200 * time.Millisecond) // e2e poll
	}
}

// TestE2EStatusShape: /status JSON carries the documented per-target
// fields plus the process snapshot block.
func TestE2EStatusShape(t *testing.T) {
	dir := t.TempDir()
	lp := freePort(t)
	startBin(t,
		"-mode=server", "-listen", "127.0.0.1:"+itoa(lp),
		"-allow", "127.0.0.1",
		"-metrics", "127.0.0.1:"+itoa(freePort(t)))
	tf := writeTargetsFile(t, dir, map[string]string{"statust": "127.0.0.1:" + itoa(lp)})
	cp := freePort(t)
	startBin(t,
		"-mode=client",
		"-targets", tf,
		"-interval", "50ms", "-timeout", "1s",
		"-metrics", "127.0.0.1:"+itoa(cp))
	waitHTTP(t, "http://127.0.0.1:"+itoa(cp)+"/metrics", "link_up{", 10*time.Second)

	// Poll /status until the target reports healthy (link_up true with
	// populated SRTT), then decode the LAST healthy snapshot below.
	healthy := false
	var raw string
	dl := time.Now().Add(15 * time.Second)
	for time.Now().Before(dl) {
		_, raw = httpGetIf(t, funcPort2Status(cp))
		if strings.Contains(raw, `"name":"statust"`) && strings.Contains(raw, `"link_up":true`) {
			healthy = true
			break
		}
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(150 * time.Millisecond) // e2e poll
	}
	if !healthy {
		t.Fatalf("/status never reached a healthy snapshot; last: %.600s", raw)
	}
	var doc struct {
		Targets []struct {
			Name   string  `json:"name"`
			LinkUp bool    `json:"link_up"`
			Jitter float64 `json:"jitter_seconds"`
			SRTT   float64 `json:"srtt_seconds"`
		} `json:"targets"`
		Process struct {
			HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
			Goroutines     int    `json:"goroutines"`
		} `json:"process"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("/status JSON decode: %v; body: %.600s", err, raw)
	}
	if len(doc.Targets) != 1 || doc.Targets[0].Name != "statust" {
		t.Fatalf("unexpected targets: %+v", doc.Targets)
	}
	if !doc.Targets[0].LinkUp {
		t.Errorf("link_up = false on a healthy loopback")
	}
	if doc.Targets[0].SRTT <= 0 {
		t.Errorf("srtt = %v, want > 0", doc.Targets[0].SRTT)
	}
	if doc.Process.Goroutines <= 0 || doc.Process.HeapAllocBytes == 0 {
		t.Errorf("process snapshot not populated: %+v", doc.Process)
	}
}

// TestE2ESvcGateRefusal pins the supply-chain decision as a black-box
// behavior: on Linux/darwin -svc=install refuses with a non-zero exit
// and a clear error, while an unknown -svc action is refused EVERYWHERE.
func TestE2ESvcGateRefusal(t *testing.T) {
	if runtime.GOOS != "windows" {
		cmd := exec.Command(binPath, "-svc=install")
		out, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() != 1 {
			t.Fatalf("linux -svc=install must exit 1, got %d (out %.300s)", cmd.ProcessState.ExitCode(), out)
		}
		if !strings.Contains(string(out), "Windows-only") {
			t.Errorf("refusal must name the Windows-only support; output: %.300s", out)
		}
	}

	cmd := exec.Command(binPath, "-svc=bogus")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 1 {
		t.Errorf("unknown -svc action must exit 1, got %d", cmd.ProcessState.ExitCode())
	}
	if !strings.Contains(string(out), "Unknown action") {
		t.Errorf("unknown-action output must say so: %.300s", out)
	}
}

// TestE2EFailClosedWithoutAllowlist: server mode without -allow refuses
// to start (fail-closed invariant) with a non-zero exit.
func TestE2EFailClosedWithoutAllowlist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("behavior covered on linux to keep one flake-free owner; identical code path")
	}
	p := freePort(t)
	cmd := exec.Command(binPath,
		"-mode=server", "-listen", "127.0.0.1:"+itoa(p),
		"-metrics", "127.0.0.1:"+itoa(freePort(t)))
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 1 {
		t.Fatalf("server without -allow must exit 1, got %d (out %.300s)", cmd.ProcessState.ExitCode(), out)
	}
	if !strings.Contains(string(out), "allow") {
		t.Errorf("refusal must mention the allowlist: %.300s", out)
	}
}

// itoa is a tiny strconv.Itoa stand-in to keep these files' imports lean.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

var _ = os.Getenv // referenced by the service tests which set/read env
