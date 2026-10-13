//go:build windows

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	// start (through our own -svc=start path) and wait RUNNING.
	if out, err = exec.Command(binPath, "-svc=start").CombinedOutput(); err != nil {
		t.Fatalf("-svc=start failed: %v\noutput: %.400s", err, out)
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
	if out, err = exec.Command(binPath, "-svc=uninstall").CombinedOutput(); err != nil {
		t.Fatalf("-svc=uninstall failed: %v\noutput: %.400s", err, out)
	}
	if _, err := m.OpenService(svcName); err == nil {
		t.Errorf("service still present after -svc=uninstall")
	}
	_ = strings.TrimSpace("")
	_ = os.Getenv("LPP_E2E_WINDOWS_SVC")
}
