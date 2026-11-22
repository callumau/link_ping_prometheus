package service

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

	"link_ping_prometheus/internal/config"
	"link_ping_prometheus/internal/httpserver"
	"link_ping_prometheus/internal/prober"
)

// TestServiceConfigHardening pins the service hardening set (previously
// the kardianos service.Config Option map; now the OS-neutral
// serviceInstallSpec the windows manager applies): recovery restart,
// delayed auto-start, and network/time dependencies. These were shipped
// unconfigured once (a crash left the service stopped forever) — this
// test fails if a refactor drops them again.
func TestServiceConfigHardening(t *testing.T) {
	version := "dev"
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

// TestRunRejectsInvalidConfiguration folds the four startup-refusal tests into
// one table. Every row must fail Run() BEFORE anything is bound, and the error
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
		// wantErrContains is the message fragment the Run() error must name.
		wantErrContains string
		// wantErrNotContains proves a guard was passed: the failure must come
		// from a later check, not from this message.
		wantErrNotContains string
	}{
		{
			// Deterministic late failure PAST the guard: an invalid target
			// fails BuildProberConfig, which runs after the rotation guard, so an
			// error that does not mention the old secret proves the guard
			// let the run proceed without binding anything.
			name: "old secret without primary",
			setup: func() {
				*config.Default.Mode = "client"
				*config.Default.Target = "not a target"
				*config.Default.EchoSecret = ""
				*config.Default.EchoSecretOld = "x"
			},
			wantErrContains: "old secret alone provides no authentication",
		},
		{
			name: "old secret with primary",
			setup: func() {
				*config.Default.Mode = "client"
				*config.Default.Target = "not a target"
				*config.Default.EchoSecret = "s"
				*config.Default.EchoSecretOld = "x"
			},
			wantErrContains:    "invalid target address",
			wantErrNotContains: "echo-secret-old",
		},
		{
			name: "no secrets",
			setup: func() {
				*config.Default.Mode = "client"
				*config.Default.Target = "not a target"
				*config.Default.EchoSecret = ""
				*config.Default.EchoSecretOld = ""
			},
			wantErrContains:    "invalid target address",
			wantErrNotContains: "echo-secret-old",
		},
		{
			name: "primary only",
			setup: func() {
				*config.Default.Mode = "client"
				*config.Default.Target = "not a target"
				*config.Default.EchoSecret = "s"
				*config.Default.EchoSecretOld = ""
			},
			wantErrContains:    "invalid target address",
			wantErrNotContains: "echo-secret-old",
		},
		{
			// Env-only variant: LINK_PING_ECHO_SECRET_OLD set while the primary
			// is absent. ResolveEchoSecret cannot distinguish a present-but-empty
			// env var from unset (both read "") — acceptable for the primary;
			// the guard must still catch the dangerous combination regardless of
			// provenance.
			name: "old secret via env only",
			setup: func() {
				*config.Default.Mode = "server"
				*config.Default.Target = ""
				*config.Default.EchoSecret = ""
				*config.Default.EchoSecretOld = ""
			},
			envOldSecret:    "x",
			wantErrContains: "old secret alone provides no authentication",
		},
		{
			name: "allow-from-targets in server mode has no targets file to derive from",
			setup: func() {
				*config.Default.Mode = "server"
				*config.Default.AllowFromTargets = true
				*config.Default.Allow = ""
				*config.Default.Source = ""
			},
			wantErrContains: "no peers to derive",
		},
		{
			name: "allow-from-targets with a self-only file has no peers left",
			setup: func() {
				*config.Default.Mode = "both"
				*config.Default.AllowFromTargets = true
				*config.Default.Allow = ""
				*config.Default.Source = "syd"
			},
			targetsBody:     `[{"name":"syd","address":"192.0.2.10:4000"}]`,
			wantErrContains: "no peers to derive",
		},
		{
			name: "allow-from-targets refuses a DNS-name target",
			setup: func() {
				*config.Default.Mode = "both"
				*config.Default.AllowFromTargets = true
				*config.Default.Allow = ""
				*config.Default.Source = "syd"
			},
			targetsBody:     `[{"name":"syd","address":"192.0.2.10:4000"},{"name":"fra","address":"peer.example.com:4000"}]`,
			wantErrContains: "not an IP literal",
		},
		{
			name: "unknown mode before bind",
			setup: func() {
				*config.Default.Mode = "bogus"
			},
			wantErrContains: "unknown mode",
		},
		{
			name: "tls cert without key",
			setup: func() {
				*config.Default.MetricsTLSCert = "cert.pem"
			},
			wantErrContains: "-metrics-tls-cert and -metrics-tls-key must be set together",
		},
		{
			name: "metrics user without password",
			setup: func() {
				*config.Default.MetricsBasicAuthUser = "u"
			},
			wantErrContains: "metrics basic auth requires both username and password",
		},
		{
			name: "client mode with invalid target",
			setup: func() {
				*config.Default.Mode = "client"
				*config.Default.Target = "not an address"
			},
			wantErrContains: "invalid target address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			// Deterministic baseline: an earlier row (or an earlier test that
			// leaked through saveFlags' snapshot-at-entry restore) must not
			// change which guard fires first.
			*config.Default.Mode = "server"
			*config.Default.Listen = "127.0.0.1:0"
			*config.Default.Metrics = "127.0.0.1:0"
			*config.Default.Allow = ""
			*config.Default.AllowFromTargets = false
			*config.Default.Target = ""
			*config.Default.Targets = ""
			*config.Default.Source = ""
			*config.Default.EchoSecret = ""
			*config.Default.EchoSecretOld = ""
			*config.Default.MetricsBasicAuthUser = ""
			*config.Default.MetricsBasicAuthPass = ""
			*config.Default.MetricsTLSCert = ""
			*config.Default.MetricsTLSKey = ""
			*config.Default.MetricsAllowInsecure = false
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
				if err := os.WriteFile(path, []byte(tc.targetsBody), 0o600); err != nil {
					t.Fatal(err)
				}
				*config.Default.Targets = path
			}

			prg := NewProgram("dev", nil)
			prg.ctx = context.Background()
			err := prg.Run()
			if err == nil {
				t.Fatalf("expected Run() to fail (startup guard or post-guard sentinel), got nil")
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

// TestWarnIgnoredFlags pins the silent-ingestion-gap warnings (F7): flags
// with no effect in the selected mode (and the -targets/-target precedence)
// must log a one-line slog.Warn at startup, and must NOT warn in the modes
// where the flags are actually consumed.
func TestWarnIgnoredFlags(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	t.Setenv("LINK_PING_ECHO_SECRET_OLD", "")
	// Reset to the registered defaults: earlier Run()-based tests leak
	// non-default values through saveFlags' snapshot-at-entry restore.
	*config.Default.Allow = ""
	*config.Default.Listen = flag.Lookup("listen").DefValue
	*config.Default.Target, *config.Default.Targets = "", ""
	*config.Default.EchoSecretOld = ""
	*config.Default.AllowFromTargets = false

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
				*config.Default.Allow = "127.0.0.1"
				*config.Default.Listen = "127.0.0.1:4100"
				*config.Default.EchoSecretOld = "old"
				// -listen's warning keys off FlagWasSet, whose process-wide
				// bookkeeping cannot be reset; drive the same seam the other
				// set-flag cases use. The per-subtest reset restores it.
				config.SetFlagNamesForTest(func() []string { return []string{"listen"} })
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
				*config.Default.Allow = "127.0.0.1"
				*config.Default.Listen = "127.0.0.1:4100"
				*config.Default.EchoSecretOld = "old"
			},
		},
		{
			name: "both mode consumes server flags",
			mode: "both",
			setup: func() {
				*config.Default.Allow = "127.0.0.1"
				*config.Default.EchoSecretOld = "old"
			},
		},
		{
			name: "targets and target both set",
			mode: "client",
			setup: func() {
				*config.Default.Target = "127.0.0.1:4000"
				*config.Default.Targets = "targets.json"
			},
			wantWarns: []string{"-targets wins"},
		},
		{
			name:  "only target set",
			mode:  "client",
			setup: func() { *config.Default.Target = "127.0.0.1:4000" },
		},
		{
			name:  "only targets set",
			mode:  "client",
			setup: func() { *config.Default.Targets = "targets.json" },
		},
		{
			name:      "allow-from-targets in client mode",
			mode:      "client",
			setup:     func() { *config.Default.AllowFromTargets = true },
			wantWarns: []string{"-allow-from-targets set but ignored"},
		},
		{
			// The mirrored direction: -mode defaults to server, so an agent started
			// with client-probing flags and no -mode exports no link_up series at
			// all while /readyz still answers 200. Drives the SetFlagNamesForTest seam
			// rather than flag.Set, whose process-wide "was set" bookkeeping
			// cannot be undone for the tests that run after this one.
			name: "client-probing flags set in server mode",
			mode: "server",
			setup: func() {
				config.SetFlagNamesForTest(func() []string { return []string{"interval", "target"} })
			},
			wantWarns: []string{"client-probing flags set but ignored", "-mode defaults to server", "-target", "-interval"},
		},
		{
			name: "client-probing flags set in client mode are consumed",
			mode: "client",
			setup: func() {
				config.SetFlagNamesForTest(func() []string { return []string{"interval", "target"} })
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			t.Cleanup(config.SetFlagNamesForTest(func() []string { return nil }))
			*config.Default.Mode = tc.mode
			tc.setup()
			buf := captureWarns(t)
			config.WarnIgnoredFlags(tc.mode)
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
// exhaustion, container network teardown), Run() must cancel the mode
// loops and return an error, so the agent exits non-zero and the SCM
// restart action fires. Before the fix a dead endpoint was only
// slog.Error'd while the agent kept probing — a monitor that looks
// healthy. The seam (Program.testServeMetrics) keeps the production
// binder's return shape while letting the test hold the *http.Server
// handle; srv.Close() terminates Serve and closes metricsDone
// deterministically. Falsification: remove the "case <-metricsDone" arm
// of the Run() select and this test times out at the runErr guard.
func TestRun_MetricsServerDeathIsFatal(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	// Same deliberate config as TestProgramStartStopBothMode: both mode
	// runs until cancelled, so the ONLY way Run() can return is the
	// metrics-death arm of the select.
	*config.Default.Mode = "both"
	*config.Default.Listen = "127.0.0.1:0"
	*config.Default.Metrics = "127.0.0.1:0"
	*config.Default.Targets = ""
	*config.Default.Target = "127.0.0.1:1" // nothing listening: client just reconnect-loops
	*config.Default.Allow = "127.0.0.1"

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	prg := NewProgram("dev", nil)
	prg.ctx = rootCtx
	prg.cancel = rootCancel

	var srvHandle *http.Server
	started := make(chan struct{})
	prg.testServeMetrics = func() (*http.Server, <-chan struct{}, error) {
		// The real binder with the same captured-string discipline as
		// production (httpserver.Start takes values, not flag reads).
		srv, done, err := httpserver.Start("127.0.0.1:0", "", "", "", "", prober.NewStatusRegistry(), false, "both")
		srvHandle = srv
		close(started)
		return srv, done, err
	}

	runErr := make(chan error, 1)
	go func() { runErr <- prg.Run() }()

	select {
	case <-started:
	case err := <-runErr:
		t.Fatalf("Run() failed before the metrics server was up: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("metrics server did not start within 5s")
	}
	// Let Run() settle into its select before killing the listener, so
	// the close cannot be mistaken for a startup-order artifact.
	time.Sleep(200 * time.Millisecond)

	// Kill the serve goroutine mid-run: Close tears down the listener and
	// active conns, Serve returns, metricsDone closes.
	if err := srvHandle.Close(); err != nil {
		t.Fatalf("closing metrics server: %v", err)
	}

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run() returned nil after mid-run metrics-server death; want fatal error")
		}
		if !strings.Contains(err.Error(), "metrics server terminated") {
			t.Errorf("error should name the metrics-server death, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not observe the dead metrics server within 5s")
	}
}

// TestProgramStartStopBothMode exercises the service Start/Stop lifecycle
// in "both" mode. With the race detector this proves the WaitGroup Add is
// correctly sequenced before Stop's Wait (previously Add ran concurrently
// inside Run()).
func TestProgramStartStopBothMode(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	*config.Default.Mode = "both"
	*config.Default.Listen = "127.0.0.1:0"
	*config.Default.Metrics = "127.0.0.1:0"
	*config.Default.Targets = ""
	*config.Default.Target = "127.0.0.1:1" // nothing listening: client just reconnect-loops
	// Valid server allowlist: Run() must SUCCEED here. A Run() failure now
	// exits the process uncleanly (os.Exit(1)) so the SCM restart action
	// fires — an invalid-config Start would abort the whole test binary.
	*config.Default.Allow = "127.0.0.1"

	prg := NewProgram("dev", nil)
	if err := prg.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
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

// TestProgramStopTimeoutReportsCleanStop pins the audit fix: a Stop whose
// drain exceeds svcStopDeadline must report a CLEAN stop (nil error).
// Mapping a Stop error to a failure causes the SCM to fire the OnFailure
// restart ladder in the middle of the maintenance window the operator just
// opened.
func TestProgramStopTimeoutReportsCleanStop(t *testing.T) {
	orig := svcStopDeadline
	svcStopDeadline = 50 * time.Millisecond
	defer func() { svcStopDeadline = orig }()

	p := &Program{}
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

// TestInstallRejectsConfigThatCannotStart pins the -svc=install validation. The
// flags are persisted into the SCM command line and replayed on every start, so
// installing a config Run() refuses — the DEFAULT -mode=server with no -allow —
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
			*config.Default.Mode = tc.mode
			*config.Default.Allow = ""
			*config.Default.AllowFromTargets = false
			*config.Default.Target, *config.Default.Targets = "127.0.0.1:4000", ""
			args, err := installServiceArgs()
			if err == nil {
				t.Fatalf("installServiceArgs accepted a configuration Run() refuses; args=%v", args)
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
		*config.Default.Mode = "server"
		*config.Default.Allow = "127.0.0.1"
		*config.Default.AllowFromTargets = false
		*config.Default.Target, *config.Default.Targets = "", ""
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
		if err := os.WriteFile(path, []byte(`[{"name":"peer","address":"192.0.2.10:4000"}]`), 0o600); err != nil {
			t.Fatal(err)
		}
		*config.Default.Mode = "client"
		*config.Default.Target, *config.Default.Targets = "", path
		*config.Default.TargetsReload = 0

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
		{"sub-millisecond interval", func() { *config.Default.BaseInterval = time.Microsecond }, "at least 1ms"},
		{"payload over the cap", func() { *config.Default.Payload = prober.MaxPayloadBytes + 1 }, "payload must be 0-"},
		{"dscp out of range", func() { *config.Default.DSCP = 64 }, "dscp must be 0-63"},
		{"reconnect below interval", func() {
			*config.Default.BaseInterval = time.Second
			*config.Default.ReconnectInterval = 100 * time.Millisecond
		}, "reconnect interval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			*config.Default.Mode = "client"
			*config.Default.Allow = ""
			*config.Default.AllowFromTargets = false
			*config.Default.Target, *config.Default.Targets = "127.0.0.1:4000", ""
			tc.setup()
			args, err := installServiceArgs()
			if err == nil {
				t.Fatalf("installServiceArgs accepted a config Run() refuses; args=%v", args)
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
// the -svc=install guard: server-only mode skipped BuildProberConfig (the only caller
// of prober.ValidateTargetName there) while Run() validates the resolved source
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
			*config.Default.Mode = "server"
			*config.Default.Allow = "127.0.0.1"
			*config.Default.AllowFromTargets = false
			*config.Default.Target, *config.Default.Targets = "", ""
			*config.Default.Source = tc.source
			*config.Default.Metrics = tc.metrics
			*config.Default.Listen = tc.listen

			args, err := installServiceArgs()
			if err == nil {
				t.Fatalf("installServiceArgs accepted a configuration Run() refuses; args=%v", args)
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
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}

// TestSvcActionSupported pins the OS gate for the -svc lifecycle actions:
// install/uninstall are Windows-only (the binary would otherwise run the
// Linux unit/init renderers, which no supported deployment
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
