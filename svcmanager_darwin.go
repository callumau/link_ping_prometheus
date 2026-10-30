//go:build darwin

package main

import (
	"fmt"
	"os/exec"
)

// macOS service bridging (launchd): the daemonization is done by a
// statically delivered LaunchDaemon plist (no plist/agent generation
// happens here - same rationale as the Linux adapter). -svc=run is a
// plain signal-driven foreground run; -svc=start/stop are launchctl
// conveniences for an operator testing outside CI.

func platformRunService(prg *program) error {
	return foregroundRun(prg)
}

const launchdLabel = "io.prometheus.link-ping-prometheus"

func platformStartService() error {
	return exec.Command("launchctl", "start", launchdLabel).Run()
}

func platformStopService() error {
	return exec.Command("launchctl", "stop", launchdLabel).Run()
}

// platformInstallService / platformUninstallService are unreachable on
// darwin (svcActionSupported refuses install/uninstall off-Windows);
// defined so the portable dispatcher compiles.
func platformInstallService(argv []string) error {
	return fmt.Errorf("service install is Windows-only")
}
func platformUninstallService() error { return fmt.Errorf("service install is Windows-only") }
