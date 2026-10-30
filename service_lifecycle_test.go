package main

import (
	"context"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestServiceConfigHardening pins the service hardening set (previously
// the kardianos service.Config Option map; now the OS-neutral
// serviceInstallSpec the windows manager applies): recovery restart,
// delayed auto-start, and network/time dependencies. These were shipped
// unconfigured once (a crash left the service stopped forever) — this
// test fails if a refactor drops them again. Rewritten against
// serviceInstallSpec with justification: the kardianous swap (supply-
// chain remediation) replaced the config type, and a package-agnostic
// spec keeps the pins testable on every platform.
func TestServiceConfigHardening(t *testing.T) {
	spec := serviceSpec()
	if spec.Name != "link_ping_prometheus" {
		t.Errorf("service name changed unexpectedly: %q", spec.Name)
	}
	if spec.RecoveryDelay != 5*time.Second {
		t.Errorf("recovery delay must stay 5s (documented recovery ladder), got %v", spec.RecoveryDelay)
	}
	// The reset period keeps repeated restarts inside one SCM
	// failure-accounting window (24h = one healthy day resets).
	if spec.RecoveryResetPeriod != 86400 {
		t.Errorf("recovery reset period = %v, want 86400", spec.RecoveryResetPeriod)
	}
	if !spec.DelayedAutoStart {
		t.Error("DelayedAutoStart must be true to avoid boot-race bind failures")
	}
	for _, dep := range []string{"Tcpip", "W32Time"} {
		if !slices.Contains(spec.Dependencies, dep) {
			t.Errorf("required dependency %q missing (%v)", dep, spec.Dependencies)
		}
	}
	// Version strings go stale after in-place upgrades; runtime truth is
	// in link_ping_build_info.
	if strings.Contains(spec.Description, version) && version != "dev" {
		t.Errorf("Description must not embed the build version: %q", spec.Description)
	}
}

// TestReleasableHeap pins the scavenge trigger's input: idle heap the runtime
// has not yet returned to the OS. The trigger used Sys-HeapReleased, which
// covers the whole process and is therefore always above the threshold, so the
// documented "skip an already-lean process" guard never fired.
// pi-lens-ignore: go-test-functions

// TestRunRejectsInvalidConfiguration folds the four startup-refusal tests into
// one table. Every row must fail run() BEFORE anything is bound, and the error
// must name the guard that fired — a generic failure would hide which startup
// invariant broke. The rows cover:
//
//   - the F4 rotation guard: -echo-secret-old without a primary -echo-secret
//     silently disables ALL wire auth — internal/prober/server.go consults the
//     old secret only inside its `if echoSecret != ""` branch, so an operator
//     mid-rotation whose new secret deploy failed would run unauthenticated
//     believing rotation protection is active;
//   - -allow-from-targets diagnostics: server-only mode never loads the targets
//     file, and a file whose only entry is the local site has no peers left
//     after the self filter. Both must name that reason rather than falling
//     through to the generic "requires -allow" refusal, which would hide why
//     the flag had no effect. A DNS-name target is refused before any bind,
//     because the derived allowlist cannot be built without a resolution and
//     config load deliberately never touches the network;
//   - unknown -mode refused before any bind, so a typo cannot open ports or
//     start servers;
//   - flag combinations that can only fail later: a TLS certificate without
//     its key, Basic auth without a password, and an unparseable target.
func TestRunRejectsInvalidConfiguration(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")

	for _, tc := range []struct {
		name string
		// setup mutates the flags (and nothing else) for one row.
		setup func()
		// targetsBody, when non-empty, is written to a temp targets file and
		// assigned to -targets after setup.
		targetsBody string
		// envOldSecret sets LINK_PING_ECHO_SECRET_OLD for the env-provenance
		// rotation case.
		envOldSecret string
		// wantErrContains is the message fragment the run() error must name.
		wantErrContains string
		// wantErrNotContains proves a guard was passed: the failure must come
		// from a later check, not from this message.
		wantErrNotContains string
	}{
		{
			// Deterministic late failure PAST the guard: an invalid target
			// fails buildConfig, which runs after the rotation guard, so an
			// error that does not mention the old secret proves the guard
			// let the run proceed without binding anything.
			name: "old secret without primary",
			setup: func() {
				*flMode = "client"
				*flTarget = "not a target"
				*flEchoSecret = ""
				*flEchoSecretOld = "x"
			},
			wantErrContains: "old secret alone provides no authentication",
		},
		{
			name: "old secret with primary",
			setup: func() {
				*flMode = "client"
				*flTarget = "not a target"
				*flEchoSecret = "s"
				*flEchoSecretOld = "x"
			},
			wantErrContains:    "invalid target address",
			wantErrNotContains: "echo-secret-old",
		},
		{
			name: "no secrets",
			setup: func() {
				*flMode = "client"
				*flTarget = "not a target"
				*flEchoSecret = ""
				*flEchoSecretOld = ""
			},
			wantErrContains:    "invalid target address",
			wantErrNotContains: "echo-secret-old",
		},
		{
			name: "primary only",
			setup: func() {
				*flMode = "client"
				*flTarget = "not a target"
				*flEchoSecret = "s"
				*flEchoSecretOld = ""
			},
			wantErrContains:    "invalid target address",
			wantErrNotContains: "echo-secret-old",
		},
		{
			// Env-only variant: LINK_PING_ECHO_SECRET_OLD set while the primary
			// is absent. resolveEchoSecret cannot distinguish a present-but-empty
			// env var from unset (both read "") — acceptable for the primary;
			// the guard must still catch the dangerous combination regardless of
			// provenance.
			name: "old secret via env only",
			setup: func() {
				*flMode = "server"
				*flTarget = ""
				*flEchoSecret = ""
				*flEchoSecretOld = ""
			},
			envOldSecret:    "x",
			wantErrContains: "old secret alone provides no authentication",
		},
		{
			name: "allow-from-targets in server mode has no targets file to derive from",
			setup: func() {
				*flMode = "server"
				*flAllowFromTargets = true
				*flAllow = ""
				*flSource = ""
			},
			wantErrContains: "no peers to derive",
		},
		{
			name: "allow-from-targets with a self-only file has no peers left",
			setup: func() {
				*flMode = "both"
				*flAllowFromTargets = true
				*flAllow = ""
				*flSource = "syd"
			},
			targetsBody:     `[{"name":"syd","address":"192.0.2.10:4000"}]`,
			wantErrContains: "no peers to derive",
		},
		{
			name: "allow-from-targets refuses a DNS-name target",
			setup: func() {
				*flMode = "both"
				*flAllowFromTargets = true
				*flAllow = ""
				*flSource = "syd"
			},
			targetsBody:     `[{"name":"syd","address":"192.0.2.10:4000"},{"name":"fra","address":"peer.example.com:4000"}]`,
			wantErrContains: "not an IP literal",
		},
		{
			name: "unknown mode before bind",
			setup: func() {
				*flMode = "bogus"
			},
			wantErrContains: "unknown mode",
		},
		{
			name: "tls cert without key",
			setup: func() {
				*flMetricsTLSCert = "cert.pem"
			},
			wantErrContains: "-metrics-tls-cert and -metrics-tls-key must be set together",
		},
		{
			name: "metrics user without password",
			setup: func() {
				*flMetricsBasicAuthUser = "u"
			},
			wantErrContains: "metrics basic auth requires both username and password",
		},
		{
			name: "client mode with invalid target",
			setup: func() {
				*flMode = "client"
				*flTarget = "not an address"
			},
			wantErrContains: "invalid target address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			// Deterministic baseline: an earlier row (or an earlier test that
			// leaked through saveFlags' snapshot-at-entry restore) must not
			// change which guard fires first.
			*flMode = "server"
			*flListen = "127.0.0.1:0"
			*flMetrics = "127.0.0.1:0"
			*flAllow = ""
			*flAllowFromTargets = false
			*flTarget = ""
			*flTargets = ""
			*flSource = ""
			*flEchoSecret = ""
			*flEchoSecretOld = ""
			*flMetricsBasicAuthUser = ""
			*flMetricsBasicAuthPass = ""
			*flMetricsTLSCert = ""
			*flMetricsTLSKey = ""
			*flMetricsAllowInsecure = false
			t.Setenv("LINK_PING_METRICS_USER", "")
			t.Setenv("LINK_PING_METRICS_PASS", "")
			t.Setenv("LINK_PING_ECHO_SECRET", "")
			t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")
			if tc.envOldSecret != "" {
				t.Setenv("LINK_PING_ECHO_SECRET_OLD", tc.envOldSecret)
			}
			tc.setup()
			if tc.targetsBody != "" {
				path := filepath.Join(t.TempDir(), "targets.json")
				// pi-lens-ignore: go-path-traversal
				if err := os.WriteFile(path, []byte(tc.targetsBody), 0o600); err != nil {
					t.Fatal(err)
				}
				*flTargets = path
			}

			// pi-lens-ignore: go-context-background-handler
			prg := &program{ctx: context.Background()}
			err := prg.run()
			if err == nil {
				t.Fatalf("expected run() to fail (startup guard or post-guard sentinel), got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("want error containing %q, got %v", tc.wantErrContains, err)
			}
			if tc.wantErrNotContains != "" && strings.Contains(err.Error(), tc.wantErrNotContains) {
				t.Errorf("valid configuration must pass the earlier guard, but error mentions %q: %v", tc.wantErrNotContains, err)
			}
		})
	}
}

// TestResolveMetricsAuthRejectsColonInUser pins the Basic-auth username
// constraint (F6): r.BasicAuth() splits the header at the FIRST colon, so a
// username containing ':' is unreachable — every request 401s and the
// endpoint is permanently locked out. The validation applies to the flag and
// the env fallback alike; an empty user keeps meaning "auth disabled".

// TestWarnIgnoredFlags pins the silent-ingestion-gap warnings (F7): flags
// with no effect in the selected mode (and the -targets/-target precedence)
// must log a one-line slog.Warn at startup, and must NOT warn in the modes
// where the flags are actually consumed.
func TestWarnIgnoredFlags(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")
	// Reset to the registered defaults: earlier run()-based tests leak
	// non-default values through saveFlags' snapshot-at-entry restore.
	*flAllow = ""
	*flListen = flag.Lookup("listen").DefValue
	*flTarget, *flTargets = "", ""
	*flEchoSecretOld = ""
	*flAllowFromTargets = false

	for _, tc := range []struct {
		name      string
		mode      string
		setup     func()
		wantWarns []string // substrings that MUST appear in the log
	}{
		{
			name: "server flags set in client mode",
			mode: "client",
			setup: func() {
				*flAllow = "127.0.0.1"
				*flListen = "127.0.0.1:4100"
				*flEchoSecretOld = "old"
				// -listen's warning keys off flagWasSet, whose process-wide
				// bookkeeping cannot be reset; drive the same seam the other
				// set-flag cases use. The per-subtest reset restores it.
				setFlagNames = func() []string { return []string{"listen"} }
			},
			wantWarns: []string{"-allow", "-listen", "-echo-secret-old"},
		},
		{
			name:  "clean client mode",
			mode:  "client",
			setup: func() {},
		},
		{
			name: "server mode consumes server flags",
			mode: "server",
			setup: func() {
				*flAllow = "127.0.0.1"
				*flListen = "127.0.0.1:4100"
				*flEchoSecretOld = "old"
			},
		},
		{
			name: "both mode consumes server flags",
			mode: "both",
			setup: func() {
				*flAllow = "127.0.0.1"
				*flEchoSecretOld = "old"
			},
		},
		{
			name: "targets and target both set",
			mode: "client",
			setup: func() {
				*flTarget = "127.0.0.1:4000"
				*flTargets = "targets.json"
			},
			wantWarns: []string{"-targets wins"},
		},
		{
			name:  "only target set",
			mode:  "client",
			setup: func() { *flTarget = "127.0.0.1:4000" },
		},
		{
			name:  "only targets set",
			mode:  "client",
			setup: func() { *flTargets = "targets.json" },
		},
		{
			name:      "allow-from-targets in client mode",
			mode:      "client",
			setup:     func() { *flAllowFromTargets = true },
			wantWarns: []string{"-allow-from-targets set but ignored"},
		},
		{
			// The mirrored direction: -mode defaults to server, so an agent started
			// with client-probing flags and no -mode exports no link_up series at
			// all while /readyz still answers 200. Drives the setFlagNames seam
			// rather than flag.Set, whose process-wide "was set" bookkeeping
			// cannot be undone for the tests that run after this one.
			name: "client-probing flags set in server mode",
			mode: "server",
			setup: func() {
				setFlagNames = func() []string { return []string{"interval", "target"} }
			},
			wantWarns: []string{"client-probing flags set but ignored", "-mode defaults to server", "-target", "-interval"},
		},
		{
			name: "client-probing flags set in client mode are consumed",
			mode: "client",
			setup: func() {
				setFlagNames = func() []string { return []string{"interval", "target"} }
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			orig := setFlagNames
			t.Cleanup(func() { setFlagNames = orig })
			setFlagNames = func() []string { return nil }
			*flMode = tc.mode
			tc.setup()
			buf := captureWarns(t)
			warnIgnoredFlags(tc.mode)
			log := buf.String()
			for _, w := range tc.wantWarns {
				if !strings.Contains(log, w) {
					t.Errorf("expected warning containing %q, log:\n%s", w, log)
				}
			}
			if len(tc.wantWarns) == 0 && log != "" {
				t.Errorf("expected no warnings, log:\n%s", log)
			}
		})
	}
}

// TestRun_MetricsServerDeathIsFatal pins the round-2 hardening: when the
// metrics serve goroutine dies MID-RUN (anything that terminates Serve
// other than our deliberate Shutdown — listener/accept failure, fd
// exhaustion, container network teardown), run() must cancel the mode
// loops and return an error, so the agent exits non-zero and the SCM
// restart action fires. Before the fix a dead endpoint was only
// slog.Error'd while the agent kept probing — a monitor that looks
// healthy. The seam (program.testServeMetrics) keeps the production
// binder's return shape while letting the test hold the *http.Server
// handle; srv.Close() terminates Serve and closes metricsDone
// deterministically. Falsification: remove the "case <-metricsDone" arm
// of the run() select and this test times out at the runErr guard.
// pi-lens-ignore: go-test-functions

// TestRun_MetricsServerDeathIsFatal pins the round-2 hardening: when the
// metrics serve goroutine dies MID-RUN (anything that terminates Serve
// other than our deliberate Shutdown — listener/accept failure, fd
// exhaustion, container network teardown), run() must cancel the mode
// loops and return an error, so the agent exits non-zero and the SCM
// restart action fires. Before the fix a dead endpoint was only
// slog.Error'd while the agent kept probing — a monitor that looks
// healthy. The seam (program.testServeMetrics) keeps the production
// binder's return shape while letting the test hold the *http.Server
// handle; srv.Close() terminates Serve and closes metricsDone
// deterministically. Falsification: remove the "case <-metricsDone" arm
// of the run() select and this test times out at the runErr guard.
// pi-lens-ignore: go-test-functions
func TestRun_MetricsServerDeathIsFatal(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	// Same deliberate config as TestProgramStartStopBothMode: both mode
	// runs until cancelled, so the ONLY way run() can return is the
	// metrics-death arm of the select.
	*flMode = "both"
	*flListen = "127.0.0.1:0"
	*flMetrics = "127.0.0.1:0"
	*flTargets = ""
	*flTarget = "127.0.0.1:1" // nothing listening: client just reconnect-loops
	*flAllow = "127.0.0.1"

	// pi-lens-ignore: go-context-background-handler
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	prg := &program{ctx: rootCtx, cancel: rootCancel}

	var srvHandle *http.Server
	started := make(chan struct{})
	prg.testServeMetrics = func() (*http.Server, <-chan struct{}, error) {
		// The real binder with the same captured-string discipline as
		// production (startMetricsServer takes values, not flag reads).
		srv, done, err := prg.startMetricsServer("127.0.0.1:0", "", "", "", "", prober.NewStatusRegistry(), false, "both")
		srvHandle = srv
		close(started)
		return srv, done, err
	}

	runErr := make(chan error, 1)
	go func() { runErr <- prg.run() }()

	select {
	case <-started:
	case err := <-runErr:
		t.Fatalf("run() failed before the metrics server was up: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("metrics server did not start within 5s")
	}
	// Let run() settle into its select before killing the listener, so
	// the close cannot be mistaken for a startup-order artifact.
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(200 * time.Millisecond)

	// Kill the serve goroutine mid-run: Close tears down the listener and
	// active conns, Serve returns, metricsDone closes.
	if err := srvHandle.Close(); err != nil {
		t.Fatalf("closing metrics server: %v", err)
	}

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("run() returned nil after mid-run metrics-server death; want fatal error")
		}
		if !strings.Contains(err.Error(), "metrics server terminated") {
			t.Errorf("error should name the metrics-server death, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not observe the dead metrics server within 5s")
	}
}

// TestProgramStartStopBothMode exercises the service Start/Stop lifecycle
// in "both" mode. With the race detector this proves the WaitGroup Add is
// correctly sequenced before Stop's Wait (previously Add ran concurrently
// inside run()).

// TestProgramStartStopBothMode exercises the service Start/Stop lifecycle
// in "both" mode. With the race detector this proves the WaitGroup Add is
// correctly sequenced before Stop's Wait (previously Add ran concurrently
// inside run()).
func TestProgramStartStopBothMode(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	*flMode = "both"
	*flListen = "127.0.0.1:0"
	*flMetrics = "127.0.0.1:0"
	*flTargets = ""
	*flTarget = "127.0.0.1:1" // nothing listening: client just reconnect-loops
	// Valid server allowlist: run() must SUCCEED here. A run() failure now
	// exits the process uncleanly (os.Exit(1)) so the SCM restart action
	// fires — an invalid-config Start would abort the whole test binary.
	*flAllow = "127.0.0.1"

	prg := &program{}
	if err := prg.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(200 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		prg.Stop(nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s — lifecycle/WaitGroup bug")
	}
}

// blockingGatherer parks every Gather until release is closed, making the
// MaxRequestsInFlight cap deterministic: without the park, the cap could only
// be tested by racing real gathers against each other.

// TestProgramStopTimeoutReportsCleanStop pins the audit fix: a Stop whose
// drain exceeds svcStopDeadline must report a CLEAN stop (nil error).
// kardianos maps a Stop error to STOPPED with a service-specific exit
// code, which the SCM counts as a FAILURE — the OnFailure restart ladder
// would then bring the service back up in the middle of the maintenance
// window the operator just opened.
func TestProgramStopTimeoutReportsCleanStop(t *testing.T) {
	orig := svcStopDeadline
	svcStopDeadline = 50 * time.Millisecond
	defer func() { svcStopDeadline = orig }()

	p := &program{}
	p.wg.Add(1) // hold the drain past the deadline
	release := make(chan struct{})
	go func() {
		<-release
		p.wg.Done()
	}()
	defer close(release)

	if err := p.Stop(nil); err != nil {
		t.Fatalf("Stop after deadline drain must return nil (clean stop), got: %v", err)
	}
}

// funcWriter adapts a function to io.Writer for sink tests.

// TestInstallRejectsConfigThatCannotStart pins the -svc=install validation. The
// flags are persisted into the SCM command line and replayed on every start, so
// installing a config run() refuses — the DEFAULT -mode=server with no -allow —
// used to "succeed" and then exit 1 every five seconds from the SCM OnFailure
// ladder, with no log at all when -log-file was unset. The checks run before
// platformInstallService, which is why this test needs no Windows: an install
// path that reached the SCM hook here would fail with the Windows-only error
// instead of the allowlist one.
func TestInstallRejectsConfigThatCannotStart(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")

	for _, tc := range []struct{ name, mode, wantErr string }{
		{"server mode without an allowlist", "server", "server mode requires -allow"},
		{"both mode without an allowlist", "both", "server mode requires -allow"},
		{"unknown mode", "bogus", "unknown mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			*flMode = tc.mode
			*flAllow = ""
			*flAllowFromTargets = false
			*flTarget, *flTargets = "127.0.0.1:4000", ""
			args, err := installServiceArgs()
			if err == nil {
				t.Fatalf("installServiceArgs accepted a configuration run() refuses; args=%v", args)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to name %q", err, tc.wantErr)
			}
			if args != nil {
				t.Errorf("a refused install must not produce an SCM command line, got %v", args)
			}
		})
	}

	t.Run("a valid server install yields the SCM command line", func(t *testing.T) {
		saveFlags(t)
		*flMode = "server"
		*flAllow = "127.0.0.1"
		*flAllowFromTargets = false
		*flTarget, *flTargets = "", ""
		args, err := installServiceArgs()
		if err != nil {
			t.Fatalf("installServiceArgs refused a valid config: %v", err)
		}
		if len(args) == 0 || args[len(args)-1] != "-svc=run" {
			t.Errorf("command line %v must end with -svc=run", args)
		}
	})

	t.Run("warns when -targets cannot be reloaded under the SCM", func(t *testing.T) {
		saveFlags(t)
		path := filepath.Join(t.TempDir(), "targets.json")
		// pi-lens-ignore: go-path-traversal
		if err := os.WriteFile(path, []byte(`[{"name":"peer","address":"192.0.2.10:4000"}]`), 0o600); err != nil {
			t.Fatal(err)
		}
		*flMode = "client"
		*flTarget, *flTargets = "", path
		*flTargetsReload = 0

		out := captureStdout(t, func() {
			if _, err := installServiceArgs(); err != nil {
				t.Fatalf("installServiceArgs: %v", err)
			}
		})
		if !strings.Contains(out, "no SIGHUP") {
			t.Errorf("install with -targets but no reload interval must warn that a service never re-reads the file, stdout:\n%s", out)
		}
	})
}

// TestInstallRejectsInvalidConfigFields pins the config.Validate parity hole:
// -svc=install validated the flags, source, addresses and allowlist but not
// the whole Config, so a persisted -interval/-payload/-dscp/-reconnect value
// that RunClient rejects installed "successfully" and then exited 1 on every
// SCM start (the 5s restart ladder, with no log when -log-file is unset).
func TestInstallRejectsInvalidConfigFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func()
		wantErr string
	}{
		{"sub-millisecond interval", func() { *flBaseInterval = time.Microsecond }, "at least 1ms"},
		{"payload over the cap", func() { *flPayload = prober.MaxPayloadBytes + 1 }, "payload must be 0-"},
		{"dscp out of range", func() { *flDSCP = 64 }, "dscp must be 0-63"},
		{"reconnect below interval", func() {
			*flBaseInterval = time.Second
			*flReconnectInterval = 100 * time.Millisecond
		}, "reconnect interval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			*flMode = "client"
			*flAllow = ""
			*flAllowFromTargets = false
			*flTarget, *flTargets = "127.0.0.1:4000", ""
			tc.setup()
			args, err := installServiceArgs()
			if err == nil {
				t.Fatalf("installServiceArgs accepted a config run() refuses; args=%v", args)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to name %q", err, tc.wantErr)
			}
			if args != nil {
				t.Errorf("a refused install must not produce an SCM command line, got %v", args)
			}
		})
	}
}

// TestInstallRejectsUnstartableSourceAndAddresses covers the two holes left in
// the -svc=install guard: server-only mode skipped buildConfig (the only caller
// of prober.ValidateTargetName there) while run() validates the resolved source
// in every mode, and nothing ever parsed the persisted bind addresses. Both
// freeze a config that can only exit 1 on every SCM start — with no log at all
// when -log-file is unset — so the install must refuse and name the flag. The
// checks run before platformInstallService, which is why this needs no Windows.
func TestInstallRejectsUnstartableSourceAndAddresses(t *testing.T) {
	for _, tc := range []struct{ name, source, metrics, listen, wantErr string }{
		{"server mode with an invalid -source", "Sydney DC", "127.0.0.1:0", "127.0.0.1:0", "-source"},
		{"malformed -metrics address", "", "127.0.0.1:not-a-port", "127.0.0.1:0", "-metrics"},
		{"malformed -listen address", "", "127.0.0.1:0", "127.0.0.1:not-a-port", "-listen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			*flMode = "server"
			*flAllow = "127.0.0.1"
			*flAllowFromTargets = false
			*flTarget, *flTargets = "", ""
			*flSource = tc.source
			*flMetrics = tc.metrics
			*flListen = tc.listen

			args, err := installServiceArgs()
			if err == nil {
				t.Fatalf("installServiceArgs accepted a configuration run() refuses; args=%v", args)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to name %q", err, tc.wantErr)
			}
			if args != nil {
				t.Errorf("a refused install must not produce an SCM command line, got %v", args)
			}
		})
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// printed. installServiceArgs' install-time warnings use fmt.Println, not slog:
// they are for the operator standing at the console running -svc=install.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	// pi-lens-ignore: go-ignored-call-result
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}

// TestSvcActionSupported pins the OS gate for the -svc lifecycle actions:
// install/uninstall are Windows-only (the binary would otherwise run the
// kardianos Linux unit/init renderers, which no supported deployment
// exercises - Linux installs use the static systemd unit - and whose
// shell-containment surface supply-chain scanners flag), while the
// run/start/stop helpers stay cross-platform.
func TestSvcActionSupported(t *testing.T) {
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{"run", true},
		{"start", true},
		{"stop", true},
		{"", true}, // unknown actions fail later in the switch, not here
		{"install", runtime.GOOS == "windows"},
		{"uninstall", runtime.GOOS == "windows"},
	} {
		if got := svcActionSupported(tc.action); got != tc.want {
			t.Errorf("svcActionSupported(%q) = %v, want %v (os=%s)", tc.action, got, tc.want, runtime.GOOS)
		}
	}
}
