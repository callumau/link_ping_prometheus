package config

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

func saveFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(SnapshotFlagsForTest())
}

type chanHandler struct{ ch chan string }

func (h chanHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h chanHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.ch <- r.Message:
	default:
	}
	return nil
}

func (h chanHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h chanHandler) WithGroup(string) slog.Handler { return h }

func captureLogs(t *testing.T) <-chan string {
	t.Helper()
	prev := slog.Default()
	ch := make(chan string, 128)
	slog.SetDefault(slog.New(chanHandler{ch: ch}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return ch
}

func waitForLog(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-ch:
			if strings.Contains(msg, want) {
				return
			}
		case <-deadline:
			t.Fatalf("no log record containing %q within 5s", want)
		}
	}
}

func countLogs(ch <-chan string, want string, window time.Duration) int {
	deadline := time.After(window)
	n := 0
	for {
		select {
		case msg := <-ch:
			if strings.Contains(msg, want) {
				n++
			}
		case <-deadline:
			return n
		}
	}
}

func TestResolveMetricsAuth(t *testing.T) {
	saveFlags(t)
	// Isolate from any real environment.
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	reset := func() { *Default.MetricsBasicAuthUser, *Default.MetricsBasicAuthPass = "", "" }

	reset()
	if u, p, err := ResolveMetricsAuth(); err != nil || u != "" || p != "" {
		t.Errorf("empty pair must be allowed (auth disabled): %q/%q, err %v", u, p, err)
	}

	reset()
	*Default.MetricsBasicAuthUser = "u"
	if u, p, err := ResolveMetricsAuth(); err == nil {
		t.Errorf("user without password must error (would enable empty-password auth), got %q/%q", u, p)
	}

	reset()
	*Default.MetricsBasicAuthPass = "p"
	if u, p, err := ResolveMetricsAuth(); err == nil {
		t.Errorf("password without user must error, got %q/%q", u, p)
	}

	reset()
	*Default.MetricsBasicAuthUser = "u"
	*Default.MetricsBasicAuthPass = "p"
	if u, p, err := ResolveMetricsAuth(); err != nil || u != "u" || p != "p" {
		t.Errorf("valid pair: got %q/%q, err %v", u, p, err)
	}

	// Flags win over env; env fills in when flags are empty.
	reset()
	t.Setenv("LINK_PING_METRICS_USER", "envu")
	t.Setenv("LINK_PING_METRICS_PASS", "envp")
	if u, p, err := ResolveMetricsAuth(); err != nil || u != "envu" || p != "envp" {
		t.Errorf("env fallback: got %q/%q, err %v", u, p, err)
	}

	*Default.MetricsBasicAuthUser = "flagu"
	if _, _, err := ResolveMetricsAuth(); err == nil {
		t.Error("partial flag with env fallback must error with atomic pair semantics (flag+env hybrid not allowed)")
	}
	*Default.MetricsBasicAuthPass = "flagp"
	if u, p, err := ResolveMetricsAuth(); err != nil || u != "flagu" || p != "flagp" {
		t.Errorf("full flag pair should win over env: got %q/%q, err %v", u, p, err)
	}
}

// TestResolveMetricsAuthRejectsColonInUser pins the Basic-auth username
// constraint (F6): r.BasicAuth() splits the header at the FIRST colon, so a
// username containing ':' is unreachable — every request 401s and the
// endpoint is permanently locked out. The validation applies to the flag and
// the env fallback alike; an empty user keeps meaning "auth disabled".
func TestResolveMetricsAuthRejectsColonInUser(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	for _, tc := range []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		{"colon in user", "ad:min", "p", true},
		{"plain user", "admin", "p", false},
		{"empty user (auth disabled)", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			*Default.MetricsBasicAuthUser = tc.user
			*Default.MetricsBasicAuthPass = tc.pass
			_, _, err := ResolveMetricsAuth()
			if tc.wantErr && err == nil {
				t.Errorf("user %q must be rejected", tc.user)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("user %q must be accepted, got %v", tc.user, err)
			}
		})
	}

	// Env-derived username gets the same check (flags win only when set).
	t.Run("colon in env user", func(t *testing.T) {
		*Default.MetricsBasicAuthUser, *Default.MetricsBasicAuthPass = "", ""
		t.Setenv("LINK_PING_METRICS_USER", "ad:min")
		t.Setenv("LINK_PING_METRICS_PASS", "p")
		if _, _, err := ResolveMetricsAuth(); err == nil {
			t.Error("env user containing ':' must be rejected")
		}
	})
}

// TestFlagWasSet pins the single "was this flag explicitly set" primitive.
// The process-wide FlagSet's "was set" bookkeeping cannot be undone, so the
// test drives the setFlagNames seam rather than flag.Set.
func TestFlagWasSet(t *testing.T) {
	t.Cleanup(SetFlagNamesForTest(func() []string { return []string{"listen", "hmac-coverage"} }))

	if !FlagWasSet("listen") || !FlagWasSet("hmac-coverage") {
		t.Error("an explicitly set flag must report true")
	}
	if FlagWasSet("interval") {
		t.Error("an unset flag must report false")
	}
}

// TestValidateLogRotationFlags pins the rotation guard: a rotation flag
// without -log-file is a startup error, and explicitly passing a default
// value counts as set (the old DefValue comparison silently accepted it).
func TestValidateLogRotationFlags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		logFile string
		set     []string
		wantErr bool
	}{
		{"no rotation flags", "", nil, false},
		{"rotation flag with log-file", "agent.log", []string{"log-file-max-mb"}, false},
		{"size without log-file", "", []string{"log-file-max-mb"}, true},
		{"backups without log-file", "", []string{"log-file-max-backups"}, true},
		{"age without log-file", "", []string{"log-file-max-age"}, true},
		{"explicit default size without log-file", "", []string{"log-file-max-mb"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			*Default.LogFile = tc.logFile
			t.Cleanup(SetFlagNamesForTest(func() []string { return tc.set }))

			err := ValidateLogRotationFlags()
			if got := err != nil; got != tc.wantErr {
				t.Errorf("ValidateLogRotationFlags() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestResolveAllowlist pins the allowlist's mode split. Client mode has no echo
// responder, so -allow must never be parsed there: parsing it made
// `-mode=client -allow=bogus` print the "-allow set but ignored" warning and
// then exit 1 on the unparsable entry. Server/both keep the fail-closed rule.
func TestResolveAllowlist(t *testing.T) {
	saveFlags(t)

	tests := []struct {
		name    string
		mode    string
		allow   string
		wantLen int
		wantErr string
	}{
		{"client mode ignores an unparsable -allow", "client", "bogus", 0, ""},
		{"client mode ignores even a valid -allow", "client", "127.0.0.1", 0, ""},
		{"server mode requires -allow", "server", "", 0, "requires -allow"},
		{"both mode requires -allow", "both", "", 0, "requires -allow"},
		{"server mode rejects an unparsable -allow", "server", "bogus", 0, "invalid"},
		{"server mode accepts a valid -allow", "server", "127.0.0.1,10.0.0.0/8", 2, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			saveFlags(t)
			*Default.AllowFromTargets = false
			*Default.Allow = tc.allow
			allow, err := ResolveAllowlist(tc.mode, prober.Config{})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ResolveAllowlist(%s, %q) = %v, %v; want error containing %q", tc.mode, tc.allow, allow, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveAllowlist(%s, %q): %v", tc.mode, tc.allow, err)
			}
			if allow.Len() != tc.wantLen {
				t.Errorf("ResolveAllowlist(%s, %q) len = %d, want %d", tc.mode, tc.allow, allow.Len(), tc.wantLen)
			}
		})
	}
}

// TestValidateScavengeInterval pins the -mem-scavenge floor: each tick is a
// stop-the-world runtime.ReadMemStats (plus debug.FreeOSMemory above the
// releasable threshold), so a sub-100ms interval would distort the RTT this
// agent exists to measure. 0 keeps meaning "disabled"; a NEGATIVE value is
// refused rather than silently disabling the scavenger.
func TestValidateScavengeInterval(t *testing.T) {
	for _, tc := range []struct {
		every   time.Duration
		wantErr bool
	}{
		{0, false},
		{-time.Second, true},
		{time.Millisecond, true},
		{MinScavengeInterval - time.Millisecond, true},
		{MinScavengeInterval, false},
		{5 * time.Minute, false},
	} {
		err := ValidateScavengeInterval(tc.every)
		if tc.wantErr && err == nil {
			t.Errorf("ValidateScavengeInterval(%v) accepted a sub-floor interval", tc.every)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ValidateScavengeInterval(%v) = %v, want nil", tc.every, err)
		}
	}
	// The flag Help is user-facing doc for a tunable, so it must name the floor
	// the code enforces (help/code drift has happened in this repo).
	if f := flag.Lookup("mem-scavenge"); f == nil || !strings.Contains(f.Usage, MinScavengeInterval.String()) {
		t.Errorf("mem-scavenge flag help must state the %v floor: %v", MinScavengeInterval, f)
	}
}

// TestBuildProberConfigMeshSelfSkip pins the mesh contract: with -allow-from-targets
// one targets file lists every site including the local one, so the client set
// must drop the entry whose name matches -source exactly — target names are
// Prometheus label values and are case-sensitive, so a case variant is a
// different series and must be kept. In client mode the flag is ignored
// wholesale (WarnIgnoredFlags says so), so the self entry stays.
func TestBuildProberConfigMeshSelfSkip(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	path := filepath.Join(t.TempDir(), "targets.json")
	body := `[
		{"name": "syd", "address": "192.0.2.10:4000"},
		{"name": "fra", "address": "192.0.2.11:4000"},
		{"name": "SYD", "address": "192.0.2.12:4000"}
	]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("both mode drops the exact self name only", func(t *testing.T) {
		saveFlags(t)
		*Default.Mode = "both"
		*Default.Targets = path
		*Default.Source = "syd"
		*Default.AllowFromTargets = true
		cfg, err := BuildProberConfig()
		if err != nil {
			t.Fatalf("BuildProberConfig: %v", err)
		}
		if !cfg.SkipSelf {
			t.Error("SkipSelf must be set so the reload path drops self too")
		}
		names := make([]string, 0, len(cfg.Targets))
		for _, tg := range cfg.Targets {
			names = append(names, tg.Name)
		}
		if got, want := strings.Join(names, ","), "fra,SYD"; got != want {
			t.Errorf("targets = %q, want %q (exact-match self removal, case variant kept)", got, want)
		}
	})

	t.Run("client mode ignores the flag and keeps self", func(t *testing.T) {
		saveFlags(t)
		*Default.Mode = "client"
		*Default.Targets = path
		*Default.Source = "syd"
		*Default.AllowFromTargets = true
		cfg, err := BuildProberConfig()
		if err != nil {
			t.Fatalf("BuildProberConfig: %v", err)
		}
		if cfg.SkipSelf {
			t.Error("client mode has no allowlist, so mesh mode must not apply")
		}
		if len(cfg.Targets) != 3 {
			t.Errorf("client mode must keep all 3 targets, got %d", len(cfg.Targets))
		}
	})
}

// TestWarnShadowedAndWeakenedConfig pins the two silent configurations the
// audit found: a flag silently overriding a credential already present in the
// environment (a rotation then has no effect and nothing says so), and
// -hmac-coverage=header with a payload, which authenticates only the header.
func TestWarnShadowedAndWeakenedConfig(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_ECHO_SECRET", "env-secret")
	*Default.EchoSecret = "flag-secret"
	*Default.HMACCoverage = "header"
	*Default.Payload = 16

	logs := captureLogs(t)
	warnShadowedAndWeakenedConfig(StartupFlags{EchoSecret: "flag-secret"})
	waitForLog(t, logs, "shadows the environment")
	waitForLog(t, logs, "authenticates only the 24-byte header")

	// Identical values must not warn about shadowing. The channel is drained
	// for a short window so the assertion sees any record that was emitted.
	*Default.EchoSecret = "env-secret"
	warnShadowedAndWeakenedConfig(StartupFlags{EchoSecret: "env-secret"})
	if n := countLogs(logs, "shadows the environment", 200*time.Millisecond); n != 0 {
		t.Errorf("identical flag/env values warned about shadowing %d time(s)", n)
	}
}

// TestWarnShadowedMetricsPass pins that -metrics-pass shadowing
// LINK_PING_METRICS_PASS logs the same shadowing warning as -metrics-user.
func TestWarnShadowedMetricsPass(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_METRICS_PASS", "env-pass")
	*Default.MetricsBasicAuthPass = "flag-pass"

	logs := captureLogs(t)
	warnShadowedAndWeakenedConfig(StartupFlags{MetricsPass: "flag-pass"})
	waitForLog(t, logs, "shadows the environment")
}
