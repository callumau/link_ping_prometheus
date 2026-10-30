//go:build windows

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows service e2e: the REAL -svc=install/start/stop/uninstall cycle
// through the compiled binary on an actual SCM (GitHub windows runners
// run elevated, so the SCR paths the installer documents are exercisable).
// Cleanup is unconditionally uninstall-first.

func svcHasAdmin(t *testing.T) bool {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect() // pi-lens-ignore: go-ignored-call-result
	return true
}

func TestE2EWindowsServiceLifecycle(t *testing.T) {
	// Install/config/uninstall is CI-safe and runs with
	// LPP_E2E_WINDOWS_INSTALL=1. The SCM start/stop half stays behind the
	// manual gate: on hosted runners the SCM-started process dies
	// pre-dispatch under LocalSystem (1053) and is only debuggable on an
	// interactive host (see docs/development.md).
	full := os.Getenv("LPP_E2E_WINDOWS") == "1"
	if !full && os.Getenv("LPP_E2E_WINDOWS_INSTALL") != "1" {
		t.Skip("set LPP_E2E_WINDOWS_INSTALL=1 for the install/config/uninstall e2e (CI), or LPP_E2E_WINDOWS=1 for the full SCM start/stop lifecycle (manual)")
	}
	if !svcHasAdmin(t) {
		t.Skip("SCM manager connect needs elevation; runner lacks it")
	}
	const svcName = "link_ping_prometheus"
	defer func() {
		// Unconditionally de-install on any exit path (install helper is
		// idempotent-tolerant: a missing service errors, ignored).
		_ = exec.Command(binPath, "-svc=uninstall").Run()
	}()

	metricsP := freePort(t)
	logDir := filepath.Join(os.TempDir(), "lpp-e2e-svc")
	_ = os.MkdirAll(logDir, 0o755)
	logFile := filepath.Join(logDir, "service.log")

	install := exec.Command(binPath,
		"-svc=install",
		"-mode=server",
		"-allow=127.0.0.1",
		fmt.Sprintf("-listen=127.0.0.1:%d", freePort(t)),
		fmt.Sprintf("-metrics=127.0.0.1:%d", metricsP),
		"-log-file="+logFile)
	out, err := install.CombinedOutput()
	if err != nil {
		t.Fatalf("-svc=install failed: %v\noutput: %.600s", err, out)
	}

	// The service was created with our hardening; verify the recorded
	// shape via the SCM (name/start-side; deeper fields are unit-pinned
	// by TestServiceConfigHardening through serviceSpec).
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
	cfg, err := s.Config()
	if err != nil {
		t.Fatalf("query service config: %v", err)
	}
	if cfg.StartType != mgr.StartAutomatic {
		t.Errorf("start type = %v, want automatic", cfg.StartType)
	}
	if len(cfg.Dependencies) < 2 {
		t.Errorf("dependencies not recorded: %v (want Tcpip + W32Time)", cfg.Dependencies)
	}

	// CI runs only the install half. Assert the teardown here so the CI run
	// still covers install -> SCM config -> uninstall.
	if !full {
		t.Log("LPP_E2E_WINDOWS unset: verified install/config/uninstall; SCM start/stop is manual-only")
		uninstallSvc(t, m, svcName)
		return
	}

	// start (through our own -svc=start path) and wait RUNNING. On failure
	// run a three-way diagnostic so the runner log alone isolates the
	// failing edge: (1) direct sc.exe start (removes our mgr layer),
	// (2) the persisted recovery actions + binary existence, (3) a short
	// CONSOLE -svc=run smoke check (the foreground path the SCM would
	// otherwise go through).
	if out, err = exec.Command(binPath, "-svc=start").CombinedOutput(); err != nil {
		qc, _ := exec.Command("sc.exe", "qc", svcName).CombinedOutput()
		sdt, _ := exec.Command("sc.exe", "sdshow", svcName).CombinedOutput()
		fa, _ := exec.Command("sc.exe", "failure", svcName).CombinedOutput()
		exists := "no"
		if _, stat := os.Stat(binPath); stat == nil {
			exists = "yes"
		}
		dsc, derr := exec.Command("sc.exe", "start", svcName).CombinedOutput()
		consoleCtx, consoleCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer consoleCancel()
		consoleCmd := exec.CommandContext(consoleCtx, binPath, "-mode=server", "-allow=127.0.0.1",
			"-log-file="+logFile)
		cout, cerr := consoleCmd.CombinedOutput()
		ccode := "running(until timeout)"
		if cerr != nil {
			ccode = fmt.Sprintf("exited: %v out: %.300s", cerr, cout)
		}
		// The SCM-run binary logs to -log-file; its content shows the
		// dispatch decision and any silent failure inside the service.
		time.Sleep(2 * time.Second)
		logContent := "(missing)"
		if b, rerr := os.ReadFile(logFile); rerr == nil {
			logContent = string(b)
		}
		t.Fatalf("-svc=start failed: %v\n-- bin exists: %s (%s)\n-- sc qc:\n%.800s\n-- sc failure:\n%.500s\n-- direct sc start: err=%v out=%.600s\n-- console -svc=run smoke: %s\n-- service.log:\n%.1500s\n-- sdshow:\n%.400s\n-- -svc=start output:\n%.400s",
			err, exists, binPath, qc, fa, derr, dsc, ccode, logContent, sdt, out)
	}
	deadline := time.Now().Add(20 * time.Second)
	state := svc.Stopped
	for {
		st, serr := s.Query()
		if serr != nil {
			t.Fatalf("query service state: %v", serr)
		}
		state = st.State
		if state == svc.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("service never reached RUNNING: state=%v", state)
		}
		time.Sleep(200 * time.Millisecond) // e2e poll
	}
	// /readyz must answer on the configured metrics port while running.
	waitHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/readyz", metricsP), "", 15*time.Second)

	// stop (through -svc=stop) then verify STOPPED.
	if out, err = exec.Command(binPath, "-svc=stop").CombinedOutput(); err != nil {
		t.Fatalf("-svc=stop failed: %v\noutput: %.400s", err, out)
	}
	deadline = time.Now().Add(25 * time.Second)
	for {
		st, serr := s.Query()
		if serr != nil {
			t.Fatalf("query stopped state: %v", serr)
		}
		if st.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("service never reached STOPPED: state=%v", st.State)
		}
		time.Sleep(250 * time.Millisecond) // e2e poll
	}

	// uninstall removes the service entirely.
	uninstallSvc(t, m, svcName)
}

// uninstallSvc removes the installed service and fails the test if the SCM
// still reports it. Shared by the CI install-only path and the full
// lifecycle path so both assert the same teardown.
func uninstallSvc(t *testing.T, m *mgr.Mgr, name string) {
	t.Helper()
	if out, err := exec.Command(binPath, "-svc=uninstall").CombinedOutput(); err != nil {
		t.Fatalf("-svc=uninstall failed: %v\noutput: %.400s", err, out)
	}
	if _, err := m.OpenService(name); err == nil {
		t.Errorf("service still present after -svc=uninstall")
	}
}
