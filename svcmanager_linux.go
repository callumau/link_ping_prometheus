//go:build linux

package main

import (
	"fmt"
	"os/exec"
)

// Linux service bridging: daemonization is done by systemd with the
// static unit from installer/linux (no unit/init script is generated
// here - the cross-platform renderers flagged by supply-chain scanners
// were removed with the kardianos swap). -svc=run is a plain
// signal-driven foreground run and -svc=start/stop are thin
// systemctl conveniences.

func platformRunService(prg *program) error {
	return foregroundRun(prg)
}

func platformStartService() error {
	return exec.Command("systemctl", "start", serviceName).Run()
}

func platformStopService() error {
	return exec.Command("systemctl", "stop", serviceName).Run()
}

// removeEventLogSource exists only on the Windows manager; unix has no
// event-log source to remove.
func removeEventLogSource(name string) {}

// platformInstallService / platformUninstallService are unreachable on
// linux (svcActionSupported refuses install/uninstall off-Windows);
// defined so the portable dispatcher compiles.
func platformInstallService(argv []string) error { return fmt.Errorf("service install is Windows-only") }
func platformUninstallService() error            { return fmt.Errorf("service install is Windows-only") }
