package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// pi-lens-ignore: go-test-functions
func TestResolveMetricsAuth(t *testing.T) {
	saveFlags(t)
	// Isolate from any real environment.
	t.Setenv("LINK_PING_METRICS_USER", "")
	t.Setenv("LINK_PING_METRICS_PASS", "")

	reset := func() { *flMetricsBasicAuthUser, *flMetricsBasicAuthPass = "", "" }

	reset()
	if u, p, err := resolveMetricsAuth(); err != nil || u != "" || p != "" {
		t.Errorf("empty pair must be allowed (auth disabled): %q/%q, err %v", u, p, err)
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	if u, p, err := resolveMetricsAuth(); err == nil {
		t.Errorf("user without password must error (would enable empty-password auth), got %q/%q", u, p)
	}

	reset()
	*flMetricsBasicAuthPass = "p"
	if u, p, err := resolveMetricsAuth(); err == nil {
		t.Errorf("password without user must error, got %q/%q", u, p)
	}

	reset()
	*flMetricsBasicAuthUser = "u"
	*flMetricsBasicAuthPass = "p"
	if u, p, err := resolveMetricsAuth(); err != nil || u != "u" || p != "p" {
		t.Errorf("valid pair: got %q/%q, err %v", u, p, err)
	}

	// Flags win over env; env fills in when flags are empty.
	reset()
	t.Setenv("LINK_PING_METRICS_USER", "envu")
	t.Setenv("LINK_PING_METRICS_PASS", "envp")
	if u, p, err := resolveMetricsAuth(); err != nil || u != "envu" || p != "envp" {
		t.Errorf("env fallback: got %q/%q, err %v", u, p, err)
	}

	*flMetricsBasicAuthUser = "flagu"
	if _, _, err := resolveMetricsAuth(); err == nil {
		t.Error("partial flag with env fallback must error with atomic pair semantics (flag+env hybrid not allowed)")
	}
	*flMetricsBasicAuthPass = "flagp"
	if u, p, err := resolveMetricsAuth(); err != nil || u != "flagu" || p != "flagp" {
		t.Errorf("full flag pair should win over env: got %q/%q, err %v", u, p, err)
	}
}

// captureWarns swaps the default slog logger for a buffered text handler so
// tests can assert startup warnings fired. Restores the previous default on
// cleanup (tests are sequential: no parallel test may rely on the default
// logger while the buffer is installed).

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
			*flMetricsBasicAuthUser = tc.user
			*flMetricsBasicAuthPass = tc.pass
			_, _, err := resolveMetricsAuth()
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
		*flMetricsBasicAuthUser, *flMetricsBasicAuthPass = "", ""
		t.Setenv("LINK_PING_METRICS_USER", "ad:min")
		t.Setenv("LINK_PING_METRICS_PASS", "p")
		if _, _, err := resolveMetricsAuth(); err == nil {
			t.Error("env user containing ':' must be rejected")
		}
	})
}

// TestWarnIgnoredFlags pins the silent-ingestion-gap warnings (F7): flags
// with no effect in the selected mode (and the -targets/-target precedence)
// must log a one-line slog.Warn at startup, and must NOT warn in the modes
// where the flags are actually consumed.

// pi-lens-ignore: go-test-functions
// TestFlagWasSet pins the single "was this flag explicitly set" primitive.
// The process-wide FlagSet's "was set" bookkeeping cannot be undone, so the
// test drives the setFlagNames seam rather than flag.Set.
func TestFlagWasSet(t *testing.T) {
	orig := setFlagNames
	t.Cleanup(func() { setFlagNames = orig })
	setFlagNames = func() []string { return []string{"listen", "hmac-coverage"} }

	if !flagWasSet("listen") || !flagWasSet("hmac-coverage") {
		t.Error("an explicitly set flag must report true")
	}
	if flagWasSet("interval") {
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
			*flLogFile = tc.logFile
			orig := setFlagNames
			t.Cleanup(func() { setFlagNames = orig })
			setFlagNames = func() []string { return tc.set }

			err := validateLogRotationFlags()
			if got := err != nil; got != tc.wantErr {
				t.Errorf("validateLogRotationFlags() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestHardenLogSink pins the log-sink invariant: the agent enforces 0600 on
// the configured log file regardless of provenance (a file placed at the
// configured path by someone else keeps its wider mode while the agent
// appends topology into it) and refuses symlinked log paths (a symlink can
// redirect topology-bearing lines into a file another local user controls).
// Windows: os.Stat reports 0666 for every file regardless of ACL and
// f.Chmod only toggles the read-only attribute, so the POSIX perm-bit
// assertions are unimplementable there — hardenLogSink instead restricts
// the file's DACL (logacl_windows.go) and the Windows branches below assert
// that DACL directly: protected from inheritance, full access only for
// SYSTEM, Administrators and the process token user.

// TestHardenLogSink pins the log-sink invariant: the agent enforces 0600 on
// the configured log file regardless of provenance (a file placed at the
// configured path by someone else keeps its wider mode while the agent
// appends topology into it) and refuses symlinked log paths (a symlink can
// redirect topology-bearing lines into a file another local user controls).
// Windows: os.Stat reports 0666 for every file regardless of ACL and
// f.Chmod only toggles the read-only attribute, so the POSIX perm-bit
// assertions are unimplementable there — hardenLogSink instead restricts
// the file's DACL (logacl_windows.go) and the Windows branches below assert
// that DACL directly: protected from inheritance, full access only for
// SYSTEM, Administrators and the process token user.
func TestHardenLogSink(t *testing.T) {
	t.Run("creates missing file at 0600", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if _, err := hardenLogSink(path); err != nil {
			t.Fatalf("hardenLogSink: %v", err)
		}
		if runtime.GOOS == "windows" {
			// Stat reports 0666 on Windows regardless of the create mode, so
			// pin the Windows equivalent: the created file's DACL is the
			// restricted protected set, not the parent directory's inherited
			// grant.
			verifyLogDACLRestricted(t, path)
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat created file: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("created file mode = %04o, want 0600", fi.Mode().Perm())
		}
	})

	t.Run("repairs pre-existing wide mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		repaired, err := hardenLogSink(path)
		if err != nil {
			t.Fatalf("hardenLogSink: %v", err)
		}
		if !repaired {
			t.Error("repaired = false, want true")
		}
		// The content assertion is platform-independent: a repair, perm-bit
		// or DACL alike, must not touch what is already in the file.
		if data, err := os.ReadFile(path); err != nil || string(data) != "x" {
			t.Errorf("file content changed: %q, err %v", data, err)
		}
		if runtime.GOOS == "windows" {
			// The repair on Windows is a DACL restriction, not perm bits —
			// pin exactly that.
			verifyLogDACLRestricted(t, path)
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat repaired file: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("repaired file mode = %04o, want 0600", fi.Mode().Perm())
		}
	})

	t.Run("keeps a compliant file untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.log")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		if runtime.GOOS == "windows" {
			// "compliant" is not observable through os.Stat (always 0666), so
			// pre-apply the log DACL by running hardenLogSink once; the DACL
			// comparison in restrictLogDACL must then report the second run as
			// compliant — pins the idempotence of that comparison.
			if _, err := hardenLogSink(path); err != nil {
				t.Fatalf("pre-limit hardenLogSink: %v", err)
			}
			repaired, err := hardenLogSink(path)
			if err != nil {
				t.Fatalf("hardenLogSink: %v", err)
			}
			if repaired {
				t.Error("repaired = true for an already-restricted DACL")
				// Dump both tables so the runner log pins the exact
				// field the template-vs-file comparison disagrees on.
				dumpLogDACLTables(t, path)
			}
			verifyLogDACLRestricted(t, path)
			return
		}
		repaired, err := hardenLogSink(path)
		if err != nil {
			t.Fatalf("hardenLogSink: %v", err)
		}
		if repaired {
			t.Error("repaired = true for an already-0600 file")
		}
	})

	t.Run("refuses symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "outside.log")
		if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
			t.Fatalf("seed target: %v", err)
		}
		path := filepath.Join(dir, "agent.log")
		if err := os.Symlink(target, path); err != nil {
			t.Skipf("symlink not supported here: %v", err)
		}
		_, err := hardenLogSink(path)
		if err == nil {
			t.Fatal("hardenLogSink accepted a symlinked log path")
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("error does not mention symlink: %v", err)
		}
		// The linked target must be untouched and the symlink itself must
		// survive (no replace-with-regular-file fallback).
		if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
			t.Errorf("linked target changed: %q, err %v", data, err)
		}
		if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("symlink replaced or missing: %v, %v", fi, err)
		}
	})
}

// TestAbsolutizeFlagValue pins the service-install argument rewriting: path
// flags must be persisted absolute (the SCM's working directory is unrelated
// to the install directory), while every other flag - notably the integer
// log-rotation flags - must be persisted verbatim. Absolutizing
// log-file-max-mb=50 produced "C:\cwd\50", so the service exited 2 at
// flag.Parse with stderr discarded under the SCM: a crash loop with no
// diagnostics at all.

// TestAbsolutizeFlagValue pins the service-install argument rewriting: path
// flags must be persisted absolute (the SCM's working directory is unrelated
// to the install directory), while every other flag - notably the integer
// log-rotation flags - must be persisted verbatim. Absolutizing
// log-file-max-mb=50 produced "C:\cwd\50", so the service exited 2 at
// flag.Parse with stderr discarded under the SCM: a crash loop with no
// diagnostics at all.
func TestAbsolutizeFlagValue(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	absLog := filepath.Join(cwd, "logs", "agent.log")

	tests := []struct{ name, flag, value, want string }{
		{"int size flag is untouched", "log-file-max-mb", "50", "50"},
		{"int backups flag is untouched", "log-file-max-backups", "0", "0"},
		{"int age flag is untouched", "log-file-max-age", "28", "28"},
		{"relative log path is absolutized", "log-file", filepath.Join("logs", "agent.log"), absLog},
		{"relative targets path is absolutized", "targets", "targets.json", filepath.Join(cwd, "targets.json")},
		{"already absolute path is unchanged", "metrics-tls-cert", absLog, absLog},
		{"empty path value stays empty", "log-file", "", ""},
		{"non-path flag is untouched", "mode", "client", "client"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := absolutizeFlagValue(tc.flag, tc.value); got != tc.want {
				t.Errorf("absolutizeFlagValue(%q, %q) = %q, want %q", tc.flag, tc.value, got, tc.want)
			}
		})
	}
}

// TestReadyzSemantics pins the liveness/readiness split: /healthz stays
// always-200, while /readyz must report 503 for a client-side agent that has
// never held a working socket (DNS outage, firewall) - alive but probing
// nothing is exactly the failure mode an orchestrator must be able to see.
// socket_age_seconds is set only after a successful dial, so it is the signal
// the gate reads.

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
			*flAllowFromTargets = false
			*flAllow = tc.allow
			allow, err := resolveAllowlist(tc.mode, prober.Config{})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveAllowlist(%s, %q) = %v, %v; want error containing %q", tc.mode, tc.allow, allow, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveAllowlist(%s, %q): %v", tc.mode, tc.allow, err)
			}
			if allow.Len() != tc.wantLen {
				t.Errorf("resolveAllowlist(%s, %q) len = %d, want %d", tc.mode, tc.allow, allow.Len(), tc.wantLen)
			}
		})
	}
}

// TestValidateScavengeInterval pins the -mem-scavenge floor: each tick is a
// stop-the-world runtime.ReadMemStats (plus debug.FreeOSMemory above the
// releasable threshold), so a sub-100ms interval would distort the RTT this
// agent exists to measure. 0 keeps meaning "disabled".
func TestValidateScavengeInterval(t *testing.T) {
	for _, tc := range []struct {
		every   time.Duration
		wantErr bool
	}{
		{0, false},
		{-time.Second, false},
		{time.Millisecond, true},
		{minScavengeInterval - time.Millisecond, true},
		{minScavengeInterval, false},
		{5 * time.Minute, false},
	} {
		err := validateScavengeInterval(tc.every)
		if tc.wantErr && err == nil {
			t.Errorf("validateScavengeInterval(%v) accepted a sub-floor interval", tc.every)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateScavengeInterval(%v) = %v, want nil", tc.every, err)
		}
	}
	// The flag Help is user-facing doc for a tunable, so it must name the floor
	// the code enforces (help/code drift has happened in this repo).
	if f := flag.Lookup("mem-scavenge"); f == nil || !strings.Contains(f.Usage, minScavengeInterval.String()) {
		t.Errorf("mem-scavenge flag help must state the %v floor: %v", minScavengeInterval, f)
	}
}

// TestBuildConfigMeshSelfSkip pins the mesh contract: with -allow-from-targets
// one targets file lists every site including the local one, so the client set
// must drop the entry whose name matches -source exactly — target names are
// Prometheus label values and are case-sensitive, so a case variant is a
// different series and must be kept. In client mode the flag is ignored
// wholesale (warnIgnoredFlags says so), so the self entry stays.
// pi-lens-ignore: go-test-functions
func TestBuildConfigMeshSelfSkip(t *testing.T) {
	saveFlags(t)
	t.Setenv("LINK_PING_ECHO_SECRET", "")
	path := filepath.Join(t.TempDir(), "targets.json")
	body := `[
		{"name": "syd", "address": "192.0.2.10:4000"},
		{"name": "fra", "address": "192.0.2.11:4000"},
		{"name": "SYD", "address": "192.0.2.12:4000"}
	]`
	// pi-lens-ignore: go-path-traversal
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("both mode drops the exact self name only", func(t *testing.T) {
		saveFlags(t)
		*flMode = "both"
		*flTargets = path
		*flSource = "syd"
		*flAllowFromTargets = true
		cfg, err := buildConfig()
		if err != nil {
			t.Fatalf("buildConfig: %v", err)
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
		*flMode = "client"
		*flTargets = path
		*flSource = "syd"
		*flAllowFromTargets = true
		cfg, err := buildConfig()
		if err != nil {
			t.Fatalf("buildConfig: %v", err)
		}
		if cfg.SkipSelf {
			t.Error("client mode has no allowlist, so mesh mode must not apply")
		}
		if len(cfg.Targets) != 3 {
			t.Errorf("client mode must keep all 3 targets, got %d", len(cfg.Targets))
		}
	})
}
