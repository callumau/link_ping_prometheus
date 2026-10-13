//go:build linux

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Linux service e2e: the binary runs as a REAL systemd service using the
// shipped static unit (the supported Linux deployment shape; -svc=install
// refusing is asserted separately). Requires root or passwordless sudo,
// and is exercised in CI with LPP_E2E_LINUX=1.

const svcUnit = "link_ping_prometheus-test.service"

func TestE2ELinuxSystemdServiceLifecycle(t *testing.T) {
	if os.Getenv("LPP_E2E_LINUX") != "1" {
		t.Skip("set LPP_E2E_LINUX=1 to run the Linux systemd service lifecycle e2e (needs root/sudo)")
	}
	sudo := func(stdin string, a ...string) (string, error) {
		args := append([]string{"-n"}, a...)
		c := exec.Command("sudo", args...)
		if stdin != "" {
			c.Stdin = strings.NewReader(stdin)
		}
		out, err := c.CombinedOutput()
		return string(out), err
	}
	if _, err := sudo("", "systemctl", "--no-pager", "list-units"); err != nil {
		t.Skipf("no working sudo/systemctl: %v", err)
	}

	metricsPort := freePort(t)
	logDir := t.TempDir()
	unit := fmt.Sprintf(`
[Unit]
Description=link_ping_prometheus e2e (test-owned)
After=network.target

[Service]
ExecStart=%s -mode=server -listen=127.0.0.1:%d -allow=127.0.0.1 -metrics=127.0.0.1:%d -log-file=%s/service.log
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`, binPath, freePort(t), metricsPort, logDir)

	unitPath := filepath.Join("/etc/systemd/system", svcUnit)
	if err := osWriteFileSudo(unitPath, unit); err != nil {
		t.Fatalf("write unit: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result (teardown best-effort)
		_, _ = sudo("", "systemctl", "stop", svcUnit)
		// pi-lens-ignore: go-ignored-call-result (teardown best-effort)
		_, _ = sudo("", "rm", "-f", unitPath)
		// pi-lens-ignore: go-ignored-call-result (teardown best-effort)
		_, _ = sudo("", "systemctl", "daemon-reload")
	})

	if _, err := sudo("", "systemctl", "daemon-reload"); err != nil {
		t.Fatalf("daemon-reload: %v", err)
	}
	if out, err := sudo("", "systemctl", "start", svcUnit); err != nil {
		t.Fatalf("systemctl start: %v\n%s", err, out)
	}

	// active? and the metrics port answers.
	waitHTTP(t, fmt.Sprintf("http://127.0.0.1:%d/readyz", metricsPort), "", 15*time.Second)
	if out, err := sudo("", "systemctl", "is-active", svcUnit); err != nil ||
		!strings.Contains(out, "active") {
		t.Fatalf("service not active: err=%v out=%s", err, out)
	}

	// stop and confirm down.
	if out, err := sudo("", "systemctl", "stop", svcUnit); err != nil {
		t.Fatalf("systemctl stop: %v\n%s", err, out)
	}
	if out, err := sudo("", "systemctl", "is-active", svcUnit); err == nil ||
		!strings.Contains(out, "inactive") {
		t.Fatalf("service not inactive after stop: err=%v out=%s", err, out)
	}
}

// osWriteFileSudo writes via tee under sudo (paths under /etc need it).
func osWriteFileSudo(path, content string) error {
	c := exec.Command("sudo", "-n", "tee", path)
	c.Stdin = strings.NewReader(content)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sudo tee %s: %v: %s", path, err, out)
	}
	return nil
}
