//go:build windows

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Credential env-delivery e2e: the linchpin of the Windows credentials
// story. install-service.bat stores LINK_PING_METRICS_USER/PASS and
// LINK_PING_ECHO_SECRET as REG_SZ values under the per-service
// HKLM\SYSTEM\CurrentControlSet\Services\<name>\Environment subkey and
// stakes the whole "credentials never persisted into the service config"
// design on the SCM reading that subkey and injecting the values into the
// service process at start. No unit test can settle that claim — this e2e
// writes the values with the SAME reg add form the wizard uses, starts
// the real service, and asserts the binary actually received and
// enforced them:
//   - /metrics answers 401 without credentials and with a WRONG password,
//     200 with the env-delivered pair (metrics-credential delivery);
//   - a probe client carrying the matching secret is echoed and counted
//     server-side, while a secret-less client's frames are dropped with
//     reason=hmac (HMAC-credential delivery AND enforcement).
//
// Gated behind LPP_E2E_WINDOWS=1 like the SCM lifecycle e2e: it needs an
// elevated host with a working SCM-start path (see that test's skip note
// for why the GitHub runner is not one). Cleanup unconditionally stops,
// uninstalls, and scrubs the Environment key, so a crashed run cannot
// leave credentials on the host.

func TestE2EWindowsCredentialEnvDelivery(t *testing.T) {
	if os.Getenv("LPP_E2E_WINDOWS") != "1" {
		t.Skip("set LPP_E2E_WINDOWS=1 to run the credential env-delivery e2e (needs elevation and a working SCM-start path; same gate as the service lifecycle e2e)")
	}
	if !svcHasAdmin(t) {
		t.Skip("SCM manager connect needs elevation; runner lacks it")
	}
	const svcName = "link_ping_prometheus"
	envKey := `HKLM\SYSTEM\CurrentControlSet\Services\` + svcName + `\Environment`
	mUser, mPass := "e2e-metrics-user", "e2e-metrics-pass-0123456789"
	hmacSecret := "e2e-echo-secret-0123456789abcdef" // >= 16 chars (wizard rule)

	// stop/uninstall/scrub runs BEFORE the test too: a stale service or
	// Environment key from a crashed prior run would inject old values.
	cleanup := func() {
		_ = exec.Command(binPath, "-svc=stop").Run()
		_ = exec.Command(binPath, "-svc=uninstall").Run()
		_ = exec.Command("reg", "delete", envKey, "/f").Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	metricsP := freePort(t)
	listenP := freePort(t)
	logDir := filepath.Join(os.TempDir(), "lpp-e2e-svc-creds")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	logFile := filepath.Join(logDir, "service.log")

	// Install WITHOUT any credential flag: credential flags are stripped
	// from the persisted service config by design (main.go flag.Visit
	// exclusion), so the ONLY delivery path for the secrets below is the
	// Environment key written next.
	install := exec.Command(binPath,
		"-svc=install",
		"-mode=server",
		"-allow=127.0.0.1",
		fmt.Sprintf("-listen=127.0.0.1:%d", listenP),
		fmt.Sprintf("-metrics=127.0.0.1:%d", metricsP),
		"-log-file="+logFile)
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("-svc=install failed: %v\noutput: %.600s", err, out)
	}

	// Write the credentials EXACTLY the way install-service.bat does: one
	// reg add per variable, REG_SZ, under the Environment subkey.
	for _, c := range []struct{ name, val string }{
		{"LINK_PING_METRICS_USER", mUser},
		{"LINK_PING_METRICS_PASS", mPass},
		{"LINK_PING_ECHO_SECRET", hmacSecret},
	} {
		cmd := exec.Command("reg", "add", envKey, "/v", c.name, "/t", "REG_SZ", "/d", c.val, "/f")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("reg add %s: %v\noutput: %.400s", c.name, err, out)
		}
	}

	if out, err := exec.Command(binPath, "-svc=start").CombinedOutput(); err != nil {
		t.Fatalf("-svc=start failed: %v\noutput: %.600s", err, out)
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatalf("SCM connect after install: %v", err)
	}
	defer m.Disconnect() // pi-lens-ignore: go-ignored-call-result
	s, err := m.OpenService(svcName)
	if err != nil {
		t.Fatalf("service not found after -svc=install: %v", err)
	}
	defer s.Close() // pi-lens-ignore: go-ignored-call-result
	waitServiceState(t, s, svc.Running, 20*time.Second)

	base := fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsP)
	// The env-delivered metrics pair must gate /metrics: 401 without
	// credentials (poll until the listener answers at all — state RUNNING
	// precedes the HTTP bind by a beat).
	waitHTTPCode(t, base, "", "", http.StatusUnauthorized, 20*time.Second)
	if code, _ := httpGetBasic(t, base, mUser, "wrong-password"); code != http.StatusUnauthorized {
		t.Fatalf("/metrics with a wrong password = %d, want 401", code)
	}
	// 200 with the exact env-delivered pair; the body carries server
	// series, proving this is /metrics and not a fallback endpoint.
	waitHTTPCode(t, base, mUser, mPass, http.StatusOK, 20*time.Second)

	// HMAC: a client carrying the SAME secret the SCM injected must be
	// authenticated and echoed. The proof is server-side, read THROUGH
	// the basic-auth gate (so one assertion validates both secrets):
	// link_server_probes_received_total reaches >= 1.
	client := startBin(t,
		"-mode=client",
		"-source=e2ecred",
		fmt.Sprintf("-target=127.0.0.1:%d", listenP),
		"-echo-secret="+hmacSecret,
		"-interval=200ms", "-timeout=1s",
		fmt.Sprintf("-metrics=127.0.0.1:%d", freePort(t)))
	_ = client
	waitMetricAuthGTE(t, base, mUser, mPass, "link_server_probes_received_total", 1, 20*time.Second)

	// Enforcement, not mere presence: a secret-less client's frames must
	// be REJECTED with reason=hmac by the env-authenticated server.
	noSecret := startBin(t,
		"-mode=client",
		"-source=e2enosecret",
		fmt.Sprintf("-target=127.0.0.1:%d", listenP),
		"-interval=200ms", "-timeout=1s")
	_ = noSecret
	waitMetricAuthGTE(t, base, mUser, mPass, `link_server_probes_dropped_total{reason="hmac"}`, 1, 20*time.Second)
}

// httpGetBasic performs one GET with optional Basic auth; returns status
// + body (0, "" on transport error).
func httpGetBasic(t *testing.T, url, user, pass string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, ""
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close() // pi-lens-ignore: go-ignored-call-result
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, string(body)
}

// waitHTTPCode polls until the endpoint answers the expected status with
// the given credentials ("" user = no auth header).
func waitHTTPCode(t *testing.T, url, user, pass string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastCode int
	for time.Now().Before(deadline) {
		lastCode, _ = httpGetBasic(t, url, user, pass)
		if lastCode == want {
			return
		}
		// e2e poll loop: sleep between probes
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s never answered %d within %v (last=%d)", url, want, timeout, lastCode)
}

// waitMetricAuthGTE polls an authed /metrics exposition until the named
// series reaches >= min (positive-condition polling: series exist at 0
// from the first scrape, so a substring wait is never enough). Reuses
// metricValue from the shared helpers for parsing.
func waitMetricAuthGTE(t *testing.T, url, user, pass, name string, min float64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var v float64
	for time.Now().Before(deadline) {
		_, body := httpGetBasic(t, url, user, pass)
		if v = metricValue(body, name); v >= min {
			return
		}
		// e2e poll loop: sleep between probes
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("metric %s never reached >= %v within %v (last=%v)", name, min, timeout, v)
}

// waitServiceState polls the SCM until the service reaches the wanted
// state, shared by the credential e2e (running) and reusable for stop.
func waitServiceState(t *testing.T, s *mgr.Service, want svc.State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st, serr := s.Query()
		if serr != nil {
			t.Fatalf("query service state: %v", serr)
		}
		if st.State == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("service never reached %v: state=%v", want, st.State)
		}
		// e2e poll loop: sleep between SCM queries
		time.Sleep(200 * time.Millisecond)
	}
}
