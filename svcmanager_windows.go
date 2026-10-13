//go:build windows

package main

import (
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows service management for link_ping_prometheus, following the
// pattern prometheus-community/windows_exporter uses (svc run loop +
// svc/mgr install + svc/eventlog): the Go team maintains all three
// packages, so thefleet's enterprise-tested SCM path has no single-mai
// ntainer cross-platform wrapper in between. Mirrors exactly the SCM
// hardening the kardianos path baked in (see serviceSpec + the pinned
// main_test.go test): automatic start, delayed autostart, Tcpip+W32Time
// dependencies, restart-on-failure with 5s delay and a 24h reset period.

// eventlogSinkAdapter bridges svc/eventlog to the portable eventlogSink
// interface (the Log type's methods carry richer signatures than the
// program needs, so the two-method shim keeps package main's contract
// OS-neutral).
type eventlogSinkAdapter struct{ log *eventlog.Log }

func (a eventlogSinkAdapter) Info(msg string)  { a.log.Info(1, msg) }
func (a eventlogSinkAdapter) Error(msg string) { a.log.Error(1, msg) }

// platformRunService executes -svc=run. Under the SCM it drives the
// svc.Run state machine; launched from a console (debugging) it falls
// back to the shared signal-driven foreground run.
func platformRunService(prg *program) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect Windows service context: %w", err)
	}
	if !isSvc {
		return foregroundRun(prg)
	}

	sysLog, err := eventlog.Open(serviceName)
	if err != nil {
		// A binary not installed through this package ran with
		// -svc=run: the event-log source is absent. Lifecycle events
		// degrade to the sink watcher / stderr instead of failing the
		// run - a monitoring agent must probe, not refuse, over its
		// event log being unregistered (the installer registers it).
		sysLog = nil
	}
	prg.svc = eventlogSinkAdapter{log: sysLog}
	return svc.Run(serviceName, &scmRunner{prg: prg})
}

// scmRunner implements svc.Handler; the state transitions mirror the
// reporting contract the previous kardianos runner provided: RUNNING is
// announced once Start has spawned the run goroutine (pre-validation
// unclean exits therefore still classify as SCM failures and fire the
// recovery ladder), Stop/Shutdown map to program.Stop, and a nil Stop
// result reports a clean STOPPED.
type scmRunner struct {
	prg *program
}

func (w *scmRunner) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (more bool, code uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	// Start spawns the run goroutine; genuine run failures exit the
	// process non-zero from inside it (OS-classified failure → restart),
	// so an error return here would only apply to argument-context misuse.
	if err := w.prg.Start(w.prg.svc); err != nil {
		status <- svc.Status{State: svc.Stopped}
		return false, 1
	}
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending,
				WaitHint: uint32((svcStopDeadline + shutdownJoinGrace).Milliseconds())}
			// program.Stop always returns nil now (the drain deadline
			// logs, classifying an operator stop as CLEAN so the SCM
			// restart ladder does not fire mid-maintenance).
			if err := w.prg.Stop(nil); err != nil {
				status <- svc.Status{State: svc.Stopped, Win32ExitCode: 2}
				return false, 2
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

// scManagers wraps the shared SCM connect, saving one handle per action.
func openSCManager() (*mgr.Mgr, error) {
	return mgr.Connect()
}

// platformInstallService registers the service with the exact hardening
// set serviceSpec() declares plus the event-log source; kardianos was
// removed so this is the only install path left in the binary.
func platformInstallService(argv []string) error {
	spec := serviceSpec()
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	m, err := openSCManager()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	if _, err := m.OpenService(spec.Name); err == nil {
		return fmt.Errorf("service %q already exists; run -svc=uninstall or an in-place upgrade first", spec.Name)
	}
	// The SCM command line is built with syscall.EscapeArg per argument
	// (the AGENTS-pinned quoting rule; values with spaces must arrive
	// quoted or the service arguments never parse and -svc=run is
	// never seen).
	binaryPath := exe
	for _, a := range argv {
		binaryPath += " " + syscall.EscapeArg(a)
	}
	s, err := m.CreateService(spec.Name, binaryPath, mgr.Config{
		DisplayName:      spec.DisplayName,
		Description:      spec.Description,
		StartType:        mgr.StartAutomatic,
		Dependencies:     spec.Dependencies,
		DelayedAutoStart: spec.DelayedAutoStart,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: spec.RecoveryDelay},
	}, spec.RecoveryResetPeriod); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	if err := eventlog.InstallAsEventCreate(spec.Name, eventlog.Error|eventlog.Info|eventlog.Warning); err != nil {
		return fmt.Errorf("register event-log source: %w", err)
	}
	return nil
}

// platformUninstallService deletes the service and removes the
// event-log source (kardianos removed it only on ITS uninstall path —
// matched here so a deleted service never leaves an orphaned source).
func platformUninstallService() error {
	spec := serviceSpec()
	m, err := openSCManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(spec.Name)
	if err != nil {
		return fmt.Errorf("service %q is not installed (or access denied): %w", spec.Name, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	if el, lerr := eventlog.Open(spec.Name); lerr == nil {
		el.Close()
	}
	removeEventLogSource(spec.Name)
	return nil
}

// removeEventLogSource deletes the installed event-log source registry
// key, mirroring what kardianos's uninstall used to do (best-effort:
// a source left behind has no functional impact other than a stale
// event-class name in the Application log filter UI).
func removeEventLogSource(source string) {
	key := `SYSTEM\CurrentControlSet\Services\EventLog\Application\` + source
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\EventLog\Application`, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer parent.Close() // pi-lens-ignore: go-ignored-call-result
	if derr := registry.DeleteKey(parent, source); derr != nil {
		slog.Warn("Event-log source removal failed", "source", source, "err", derr)
	}
}

// platformStartService / platformStopService: direct SCM control with a
// bounded stop wait (the batch installer wraps the same waits).
func platformStartService() error {
	spec := serviceSpec()
	m, err := openSCManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(spec.Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func platformStopService() error {
	spec := serviceSpec()
	m, err := openSCManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(spec.Name)
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("send stop control: %w", err)
	}
	deadline := time.Now().Add(svcStopDeadline)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("service did not reach STOPPED within %v (STOP_PENDING may be stuck)", svcStopDeadline)
		}
		time.Sleep(500 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("poll service status: %w", err)
		}
	}
	return nil
}

// setServiceSIDType writes SERVICE_CONFIG_SERVICE_SID_INFO; svc/mgr does
// not expose it, so ChangeServiceConfig2W is summoned directly.
func setServiceSIDType(s *mgr.Service, sidType uint32) error {
	type serviceSidInfo struct {
		dwServiceSidType uint32
	}
	info := serviceSidInfo{dwServiceSidType: uint32(sidType)}
	const serviceConfigServiceSidInfo = 12
	if err := windows.ChangeServiceConfig2(s.Handle, serviceConfigServiceSidInfo, (*byte)(unsafe.Pointer(&info))); err != nil {
		return err
	}
	return nil
}
