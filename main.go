// Command link_ping_prometheus is a UDP echo probing agent that exposes
// Prometheus metrics for latency, packet loss, and jitter.
//
// It operates in three modes:
//   - server: runs a UDP echo responder that validates a magic header.
//   - client: sends periodic probes to targets, recording RTT and loss.
//   - both: runs server and client simultaneously.
//
// pi-lens-ignore: typos, typos:unknown
// Adaptive RTO (RFC 6298) adjusts timeouts based on measured link
// quality when -adaptive is enabled (default). UDP has no
// retransmission, so the loss ratio is true network loss.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"link_ping_prometheus/internal/prober"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/natefinch/lumberjack.v2"
)

// version is the build version, injected at link time via
// -ldflags "-X main.version=...". Goreleaser sets it to the git tag;
// dev_build.sh sets it to a UTC timestamp to the minute. A plain
// `go build` (and CI test builds) leaves it as "dev".
var version = "dev"

// minScavengeUnreleased is the amount of idle heap the runtime must still be
// holding beyond what it already returned to the OS before a scavenge is worth
// its stop-the-world-adjacent cost. An already-lean process must pay nothing.
// It is a byte count, not a duration.
const minScavengeUnreleased = 4 << 20

// minScavengeInterval is the smallest accepted -mem-scavenge interval. Every
// tick is a stop-the-world runtime.ReadMemStats plus, above the releasable
// threshold, a debug.FreeOSMemory, in a process whose whole job is measuring
// RTT — a 1ms interval turns the latency it exports into GC pauses. Rejected at
// the flag boundary rather than clamped inside startHeapScavenger, so the
// scavenger loop stays a pure primitive its own test drives directly.
const minScavengeInterval = 100 * time.Millisecond

// maxConcurrentScrapes bounds simultaneous /metrics gathers. A large fleet's
// response is ~10-15MB of text and every concurrent scrape builds its own copy,
// so unbounded overlap multiplies both the live heap and the wall time of each
// response (risking a truncated scrape, i.e. the monitor reporting ITSELF
// down). Excess scrapes get a 503 instead; Prometheus retries.
const maxConcurrentScrapes = 2

// shutdownJoinGrace bounds the wait for the metrics serve goroutine to exit
// after Shutdown: an in-flight scrape holds Serve open up to the 30s
// WriteTimeout, which exceeds the service Stop deadline (20s). The drain is
// best-effort, so the join is cut short rather than making Stop report a
// timeout while the process drains a clean shutdown.
const shutdownJoinGrace = 2 * time.Second

// releasableHeap returns the idle heap bytes a scavenge could actually return
// to the OS, i.e. HeapIdle minus what has already been released. Deliberately
// NOT Sys-HeapReleased: Sys covers the whole process and stays far above any
// sane threshold for as long as the agent runs, which made the "skip an
// already-lean process" guard a no-op that scavenged on every tick. Clamped at
// 0: HeapReleased can transiently exceed HeapIdle, and an unsigned subtraction
// would otherwise wrap to an enormous value and force a scavenge every tick.
func releasableHeap(m runtime.MemStats) uint64 {
	if m.HeapIdle <= m.HeapReleased {
		return 0
	}
	return m.HeapIdle - m.HeapReleased
}

// shouldScavenge reports whether the process holds at least minUnreleased
// unreleased idle heap bytes.
func shouldScavenge(m runtime.MemStats, minUnreleased uint64) bool {
	return releasableHeap(m) >= minUnreleased
}

// validateScavengeInterval enforces the -mem-scavenge floor (see
// minScavengeInterval). 0 keeps meaning "disabled"; only a nonzero interval
// below the floor is refused.
func validateScavengeInterval(every time.Duration) error {
	if every <= 0 || every >= minScavengeInterval {
		return nil
	}
	return fmt.Errorf("-mem-scavenge %v is too small: each scavenge is a stop-the-world runtime.ReadMemStats (plus debug.FreeOSMemory above the releasable threshold), so an interval this small would distort the RTT/loss this agent exists to measure; use 0 to disable or a value >= %v", every, minScavengeInterval)
}

// startHeapScavenger returns the unused heap high-water mark to the OS on a
// fixed interval. The runtime scavenges in proportion to the allocation rate,
// so a scrape-driven high-water mark survives indefinitely while the agent is
// idle — visible on Windows as steady commit/RSS growth. every <= 0 disables
// it. The goroutine exits with ctx so it stops on shutdown in every mode.
func startHeapScavenger(ctx context.Context, every time.Duration, minUnreleased uint64, logger *slog.Logger) {
	if every <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			if !shouldScavenge(before, minUnreleased) {
				continue
			}
			debug.FreeOSMemory()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			logger.Debug("heap scavenge",
				"releasable_before_mb", releasableHeap(before)>>20,
				"idle_before_mb", before.HeapIdle>>20, "released_before_mb", before.HeapReleased>>20,
				"idle_after_mb", after.HeapIdle>>20, "released_after_mb", after.HeapReleased>>20)
		}
	}()
}

// CLI flags.
var (
	flMode             = flag.String("mode", "server", "Mode: server, client, both")
	flListen           = flag.String("listen", ":4000", "Server: Listen address")
	flAllow            = flag.String("allow", "", "Server: Comma-separated client IP allowlist (fail-closed: required in server/both mode)")
	flAllowFromTargets = flag.Bool("allow-from-targets", false, "Server: derive the fail-closed allowlist from the -targets file addresses and skip the target whose name matches -source, so one targets file serves every site of a mesh (client/both mode; every target address must be an IP literal - a DNS name is an error, because config load never resolves). Combines with -allow for extra CIDRs.")
	flTarget           = flag.String("target", "", "Client: Single target address")
	flTargets          = flag.String("targets", "", "Client: JSON file path with targets")
	flMetrics          = flag.String("metrics", "127.0.0.1:2112", "Metrics: Listen address (default binds localhost only; use \":2112\" or \"0.0.0.0:2112\" to expose on all interfaces)")
	flSvc              = flag.String("svc", "", "Service: install, uninstall (Windows only; Linux uses the systemd unit), start, stop, run")
	flJSONLogs         = flag.Bool("json-logs", false, "Log in JSON format")
	flLogFile          = flag.String("log-file", "", "Log: append logs to this file in addition to stdout (stdout is discarded under the Windows service)")
	flLogMaxSize       = flag.Int("log-file-max-mb", 10, "Log: max size in MB before rotation (0 disables rotation; requires -log-file)")
	flLogMaxBackups    = flag.Int("log-file-max-backups", 5, "Log: max rotated files to keep")
	flLogMaxAge        = flag.Int("log-file-max-age", 28, "Log: max days to keep rotated files")

	flAdaptive          = flag.Bool("adaptive", true, "Client: Use adaptive timeout based on link quality (RFC 6298)")
	flBaseInterval      = flag.Duration("interval", 500*time.Millisecond, "Client: Probe interval")
	flBaseTimeout       = flag.Duration("timeout", 1*time.Second, "Client: Base/Initial timeout")
	flReconnectInterval = flag.Duration("reconnect-interval", 5*time.Minute, "Client: How long to keep a UDP socket before re-dialing for DNS re-resolution (0 means global default 5m; use a large value e.g. 24h to effectively disable)")
	flSource            = flag.String("source", "", "Source label applied to all metrics, e.g. local datacenter (sydney-dc) (defaults to hostname)")

	flDSCP = flag.Int("dscp", 0, "Client: DSCP value 0-63 marked on probe packets (0 = no marking, default; e.g. 46 = EF). Best effort, requires OS support (Linux)")

	flPayload       = flag.Int("payload", 0, "Client: probe payload bytes beyond the 24/32-byte header (up to 1400), filled with a deterministic pattern and validated on echo; corruption is counted in link_probes_corrupted_total, distinct from loss")
	flTargetsReload = flag.Duration("targets-reload-interval", 0, "Client: poll the -targets file at this interval and apply changes without a restart (0 disables; SIGHUP also reloads on Unix; Windows services need this flag to reload)")
	flMTUSweep      = flag.Duration("mtu-sweep", time.Minute, "Client: periodically sweep DF-set probe sizes per target to find the largest frame the path carries (0 disables; Linux, or Windows with IPv4 on 2003+ / IPv6 on 1703+; results in link_path_mtu_bytes and /status; separate counters, never in the loss ratio)")
	flMemScavenge   = flag.Duration("mem-scavenge", 5*time.Minute, "Process: force a heap scavenge at this interval so the unused heap high-water mark is returned to the OS (0 disables; the interval must be at least 100ms, because each scavenge stops the world). Scrapes ratchet the heap high-water up and the runtime does not return it while the agent is otherwise idle; on Windows that reads as RSS/commit growth.")

	flMetricsBasicAuthUser = flag.String("metrics-user", "", "Metrics: Basic auth username (empty disables auth; env LINK_PING_METRICS_USER)")
	flMetricsBasicAuthPass = flag.String("metrics-pass", "", "Metrics: Basic auth password (env LINK_PING_METRICS_PASS; prefer env over CLI to avoid ps exposure)")
	flMetricsTLSCert       = flag.String("metrics-tls-cert", "", "Metrics: TLS certificate file (requires -metrics-tls-key)")
	flMetricsTLSKey        = flag.String("metrics-tls-key", "", "Metrics: TLS private key file (requires -metrics-tls-cert)")
	flMetricsAllowInsecure = flag.Bool("metrics-allow-insecure", false, "Metrics: allow Basic Auth over plaintext HTTP (otherwise requires TLS when auth is set)")
	flMetricsGzip          = flag.Bool("metrics-gzip", false, "Metrics: gzip-compress /metrics responses when the scraper offers it. Off by default: promhttp pools a gzip writer per CPU, and each holds ~0.7MB of flate state, so compression costs up to ~0.7MB x GOMAXPROCS of live heap - more than a small fleet's whole response. Enable it for many targets, where the response size matters.")
	flEchoSecret           = flag.String("echo-secret", "", "Wire: HMAC secret for UDP echo authentication (env LINK_PING_ECHO_SECRET; mitigates reflector spoof when set on both client and server)")
	flEchoSecretOld        = flag.String("echo-secret-old", "", "Wire: previous HMAC secret, still accepted by the SERVER during a zero-downtime rotation alongside -echo-secret (env LINK_PING_ECHO_SECRET_OLD; server side only)")
	flHMACCoverage         = flag.String("hmac-coverage", "full-frame", "Wire: which frame bytes the client's HMAC tag covers when -echo-secret is set: 'full-frame' (default: header plus the -payload bytes, so a tampered payload or a payload riding a captured tag no longer authenticates; needs -payload > 0 to differ) or 'header' (the 24-byte header only — the v0.7 layout, byte-identical wire output; the escape hatch for probing through a v0.7 echo server while using -payload). The server side accepts both coverages whenever it has -echo-secret, so upgrading to ≥ v0.8 clears the one broken pairing (v0.7 server + full-frame client = payload probes read as loss).")
)

// flagDefaultInt returns the registered default value of an int flag so
// validation logic stays correct if the flag defaults ever change.
func flagDefaultInt(name string) (int, error) {
	f := flag.Lookup(name)
	if f == nil {
		return 0, fmt.Errorf("missing int flag %s", name)
	}
	v, err := strconv.Atoi(f.DefValue)
	if err != nil {
		return 0, fmt.Errorf("flag %s has non-int default %q", name, f.DefValue)
	}
	return v, nil
}

// hardenLogSink enforces the 0600 log invariant regardless of file
// provenance. Logs carry peer IPs and internal topology, so they are never
// world-readable, but os.OpenFile applies its mode only at creation: a file
// placed at the configured path by someone else keeps its wider mode while
// the agent appends topology into it, and the lumberjack writer opens the
// existing file with no mode check and copies the live file's mode onto
// every rotated artifact — so repairing the live file at startup also
// protects future rotations. A symlinked path is refused outright: it can
// redirect topology-bearing log lines into a file owned by another local
// user. Fail-closed: the caller exits on error, like the allowlist refusal.
// Windows: os.OpenFile's 0600 mode, os.Stat (always 0666) and f.Chmod (an
// attribute toggle) are all meaningless for a DACL, so the POSIX enforcement
// below cannot restrict one there — Windows delegates to restrictLogDACL
// (logacl_windows.go), which replaces the file's DACL with a protected set
// granting full access only to SYSTEM, Administrators and the account this
// process runs as. The installer's ACL'd log DIRECTORY remains
// defense-in-depth: log rotation creates fresh files that inherit the
// directory's DACL, and restricting those on the fly would add a rotation
// path to hardenLogSink.
func hardenLogSink(path string) (repaired bool, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		// Not there yet: create it at the enforced mode so the lumberjack
		// path finds an existing 0600 file (its rotation copies the current
		// file's mode onto artifacts).
		// pi-lens-ignore: go-path-traversal (operator-supplied -log-file path)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return false, err
		}
		if runtime.GOOS == "windows" {
			// A fresh file inherits its parent directory's DACL, which may be
			// wide (a manual install pointing -log-file into a Users-writable
			// directory); restrict it now so the repair path does not have to
			// wait for the next start.
			defer f.Close()
			return restrictLogDACL(f)
		}
		return false, f.Close()
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refusing symlinked log path %q: a symlink can redirect topology-bearing log lines into another local user's file; create the log path directly", path)
	}
	// Open the file we Lstat'ed (no O_CREATE: it exists) and repair its mode
	// on the open descriptor, not by path, so the chmod lands on what we
	// verified.
	// pi-lens-ignore: go-path-traversal (operator-supplied -log-file path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "windows" {
		// os.Stat always reports 0666 on Windows, so the perm-bit comparison
		// is meaningless there: restrictLogDACL reads the actual DACL of the
		// open descriptor, compares it against the restricted set it pins,
		// and only rewrites it when it differs (repaired=false for an
		// already-compliant file).
		return restrictLogDACL(f)
	}
	if got.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func main() {
	flag.Parse()
	// Bound the Go heap so long-running RSS stays flat even during
	// /metrics scrape or probe bursts. The standard GOMEMLIMIT env var
	// (with units) overrides this default. 128MB leaves headroom for the
	// largest supported config (1000 targets: ~2000 goroutine stacks plus
	// native-histogram buckets) while keeping the agent lightweight.
	//
	// GOGC is deliberately NOT overridden here: measured on one target, a
	// lower GOGC shrinks the heap high-water mark under a bursty scrape load
	// but costs more GC metadata and allocation churn at the sparse scrape
	// rate a quiet agent actually sees. Operators can set GOGC themselves.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(128 << 20)
	}
	if *flLogMaxSize < 0 || *flLogMaxBackups < 0 || *flLogMaxAge < 0 {
		fmt.Fprintln(os.Stderr, "log rotation flags must be >= 0")
		os.Exit(1)
	}
	if err := validateScavengeInterval(*flMemScavenge); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *flLogFile == "" {
		dfltSize, errSize := flagDefaultInt("log-file-max-mb")
		dfltBackups, errBackups := flagDefaultInt("log-file-max-backups")
		dfltAge, errAge := flagDefaultInt("log-file-max-age")
		if err := errors.Join(errSize, errBackups, errAge); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if *flLogMaxSize != dfltSize ||
			*flLogMaxBackups != dfltBackups ||
			*flLogMaxAge != dfltAge {
			fmt.Fprintln(os.Stderr, "log rotation flags require -log-file")
			os.Exit(1)
		}
	}
	logW := io.Writer(os.Stdout)
	var logRepaired bool
	if *flLogFile != "" {
		// Enforce the 0600 invariant at the sink BEFORE either writer opens
		// the file: O_CREATE applies the mode only at creation, lumberjack
		// re-opens pre-existing files with no mode check and copies the live
		// file's mode onto every rotated artifact, and a symlink would
		// redirect topology-bearing lines into another local user's file.
		repaired, err := hardenLogSink(*flLogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "harden log file %q: %v\n", *flLogFile, err)
			os.Exit(1)
		}
		logRepaired = repaired
		if *flLogMaxSize == 0 {
			// 0600 matches lumberjack's default: logs carry peer IPs and
			// internal topology, so they are not world-readable.
			// pi-lens-ignore: go-path-traversal
			f, err := os.OpenFile(*flLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "open log file %q: %v\n", *flLogFile, err)
				os.Exit(1)
			}
			defer f.Close()
			// File FIRST: io.MultiWriter stops at the first error, and under
			// the SCM the std handle can be invalid rather than a silent NUL
			// sink — stdout-first then silently swallows every line before
			// the file ever sees one, the exact total-log-loss the install
			// warning exists to prevent. Console-first was only ever cosmetic.
			logW = io.MultiWriter(f, os.Stdout)
		} else {
			// ponytail: lumberjack handles rotation (10 MB ×5 ×28d default); no per-line overhead, reopens on rotation
			// pi-lens-ignore: go-path-traversal
			lj := &lumberjack.Logger{
				Filename:   *flLogFile,
				MaxSize:    *flLogMaxSize,
				MaxBackups: *flLogMaxBackups,
				MaxAge:     *flLogMaxAge,
				Compress:   false,
			}
			logW = io.MultiWriter(lj, os.Stdout)
		}
	}
	// Surface runtime sink failures (disk full, log dir removed): the
	// wrapper counts write errors and run()'s watcher reports them to the
	// event log / stderr. Wrapping once here covers both sink modes.
	var logSink *countedWriter
	if *flLogFile != "" {
		logSink = newCountedWriter(logW)
		logW = logSink
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if *flJSONLogs {
		slog.SetDefault(slog.New(slog.NewJSONHandler(logW, opts)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(logW, opts)))
	}
	if logRepaired {
		// Land the repair notice in the log itself, so an operator whose
		// pre-created file was wide finds the evidence next to the logs it
		// would have leaked.
		slog.Warn("Log file had wider permissions; repaired to 0600", "path", *flLogFile)
	}

	// Only after hardenLogSink and slog.SetDefault: emitted before them, the
	// marker wrote through its own O_CREATE (which follows symlinks) into a
	// path hardenLogSink would refuse, and bypassed the configured handler.
	svcTraceMarker("main-post-logsetup")

	svcTraceMarker("main-pre-svc")
	if *flSvc != "" {
		handleService(*flSvc, logSink)
		return
	}

	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	prg := &program{
		ctx:     ctx,
		logSink: logSink,
	}
	if err := prg.run(); err != nil {
		slog.Error("Program exited with error", "err", err)
		os.Exit(1)
	}
}

// meshAllowFromTargets reports whether -allow-from-targets applies. The
// derived allowlist is a server control, so the flag needs the echo responder
// (server/both mode); in client mode it is ignored (warnIgnoredFlags says so)
// and no target is skipped. One spelling of the condition, used by both the
// config builder and the startup allowlist derivation so they cannot drift.
func meshAllowFromTargets() bool {
	return *flAllowFromTargets && *flMode != "client"
}

// resolveEchoSecret returns the echo HMAC secret from flag or env.
func resolveEchoSecret() string {
	if *flEchoSecret != "" {
		return *flEchoSecret
	}
	return os.Getenv("LINK_PING_ECHO_SECRET")
}

// resolveEchoSecretOld returns the rotation-previous echo HMAC secret
// from flag or env. Empty when no rotation is in progress.
func resolveEchoSecretOld() string {
	if *flEchoSecretOld != "" {
		return *flEchoSecretOld
	}
	return os.Getenv("LINK_PING_ECHO_SECRET_OLD")
}

// warnIgnoredFlags emits one-line slog.Warn diagnostics for flags that are
// set but silently unused in the selected mode. Warnings, not errors: every
// case is backward compatible (the previous behavior ignored the flag too),
// but silent ingestion gaps are how a half-configured fleet ships.
//   - echo-secret-old is consumed ONLY by the server (rotation acceptance in
//     internal/prober/server.go), so it is ignored in client mode.
//   - allow, allow-from-targets and listen gate the echo responder, so they
//     are ignored in client mode.
//   - the props of client probing (below) are inert in server-only mode, which
//     is the DEFAULT: no target is loaded, no link_up series is exported, and
//     /readyz answers 200 unconditionally.
//   - with both -targets and -target set, buildConfig's else-if means -targets wins.
func warnIgnoredFlags(mode string) {
	if *flEchoSecretOld != "" && mode == "client" {
		slog.Warn("-echo-secret-old set but ignored: the old secret is only accepted by the echo server (server/both mode), not by the client")
	}
	// -listen's default (":4000") is non-empty, so compare against the
	// registered default: a client run with the default must not warn.
	if *flAllow != "" && mode == "client" {
		slog.Warn("-allow set but ignored: the client allowlist only applies to the echo server (server/both mode)")
	}
	if *flAllowFromTargets && mode == "client" {
		slog.Warn("-allow-from-targets set but ignored: the derived allowlist and self-skip only apply to the echo server (server/both mode)")
	}
	if *flListen != "" && *flListen != flag.Lookup("listen").DefValue && mode == "client" {
		slog.Warn("-listen set but ignored: the listen address only applies to the echo server (server/both mode)")
	}
	if *flTargets != "" && *flTarget != "" && mode != "server" {
		slog.Warn("-targets and -target are both set: -targets wins, -target is ignored")
	}
	// -hmac-coverage shapes the tag the CLIENT writes; the echo server
	// accepts both coverages whenever -echo-secret is set, so the flag has
	// no effect in server-only mode.
	if *flHMACCoverage != flag.Lookup("hmac-coverage").DefValue && mode == "server" {
		slog.Warn("-hmac-coverage set but ignored: tag coverage is a client-side choice; the echo server accepts both coverages whenever -echo-secret is set")
	}
	if mode == "server" {
		// Mirrored direction: -mode defaults to server, so an agent started with
		// client-probing flags and no -mode runs, exports ZERO link_up series
		// and still answers /readyz 200 (server mode is ready by definition) —
		// a monitor that looks healthy while measuring nothing. flag.Visit, not
		// a value comparison, so the defaults (adaptive, 500ms, 1s, 1m sweep)
		// of those flags never warn on a plain server run.
		var set []string
		for _, name := range setFlagNames() {
			if slices.Contains(clientProbeFlags, name) {
				set = append(set, "-"+name)
			}
		}
		if len(set) > 0 {
			slog.Warn(fmt.Sprintf("client-probing flags set but ignored (%s): -mode defaults to server, which probes no target, so no link_up series is exported and /readyz always reports ready; use -mode=client or -mode=both", strings.Join(set, ",")))
		}
	}
}

// clientProbeFlags are the flags with no effect outside client/both mode. Named
// individually so the server-mode warning can say exactly which ones the
// operator lost. -hmac-coverage is deliberately absent: it has its own warning
// above (one cause, one line).
var clientProbeFlags = []string{
	"target",
	"targets",
	"adaptive",
	"interval",
	"timeout",
	"reconnect-interval",
	"payload",
	"targets-reload-interval",
	"mtu-sweep",
	"dscp",
}

// setFlagNames reports the flags the operator actually set (flag.Visit reports
// only those, so a default value never triggers an "ignored" warning). A var
// because the process-wide FlagSet's "was set" bookkeeping cannot be undone: a
// test that called flag.Set to exercise the warning would leak into every later
// test in the binary.
var setFlagNames = func() []string {
	var names []string
	flag.Visit(func(f *flag.Flag) { names = append(names, f.Name) })
	return names
}

func sanitizeHostname(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	if len(out) > 63 {
		out = out[:63]
		for len(out) > 0 && out[len(out)-1] == '-' {
			out = out[:len(out)-1]
		}
		if out == "" {
			return "unknown"
		}
	}
	return out
}

func effectiveSource() string {
	if *flSource != "" {
		return *flSource
	}
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		slog.Info("source defaulted to hostname", "source", "unknown", "hostname", h)
		return "unknown"
	}
	sanitized := sanitizeHostname(h)
	if err := prober.ValidateTargetName(sanitized); err != nil {
		slog.Info("source defaulted to hostname", "source", "unknown", "hostname", h, "sanitized", sanitized, "validate_err", err)
		return "unknown"
	}
	if sanitized != h {
		slog.Info("source defaulted to hostname", "source", sanitized, "hostname", h)
	} else {
		slog.Info("source defaulted to hostname", "source", sanitized)
	}
	return sanitized
}

// resolveSource returns the effective source label (the -source flag or the
// sanitized hostname) and validates it. One spelling for buildConfig, the
// server-only run path and -svc=install: a source that fails
// ValidateTargetName must be refused by every caller, never persisted into a
// service command line that then exits 1 on each SCM start.
func resolveSource() (string, error) {
	source := *flSource
	if source == "" {
		source = effectiveSource()
	}
	if err := prober.ValidateTargetName(source); err != nil {
		return "", fmt.Errorf("invalid -source: %w", err)
	}
	return source, nil
}

// buildConfig resolves CLI flags into a prober.Config. It handles single
// (-target) and multi-target (-targets) modes. Failures are returned as
// errors so the caller can abort before any server starts.
func buildConfig() (prober.Config, error) {
	var targets []prober.Target
	if *flTargets != "" {
		var err error
		targets, err = prober.LoadTargets(*flTargets)
		if err != nil {
			return prober.Config{}, fmt.Errorf("load targets: %w", err)
		}
	} else if *flTarget != "" {
		if err := prober.ValidateTarget(*flTarget); err != nil {
			return prober.Config{}, fmt.Errorf("invalid target: %w", err)
		}
		targets = []prober.Target{{Name: "default", Address: *flTarget}}
	}
	source, err := resolveSource()
	if err != nil {
		return prober.Config{}, err
	}
	// Mesh mode (-allow-from-targets) deploys ONE targets file on every
	// site, listing all of them including the local one. Drop the self entry
	// so the shared file probes only remote peers, and record the choice in
	// the config so the reload path applies the same filter — a reload that
	// re-added self would probe and export the local site.
	skipSelf := meshAllowFromTargets()
	if skipSelf {
		targets = prober.FilterSelfTargets(targets, source)
	}
	cfg := prober.Config{
		Source:            source,
		Targets:           targets,
		SkipSelf:          skipSelf,
		Adaptive:          *flAdaptive,
		BaseInterval:      *flBaseInterval,
		BaseTimeout:       *flBaseTimeout,
		EchoSecret:        resolveEchoSecret(),
		ReconnectInterval: *flReconnectInterval,
		DSCP:              *flDSCP,
		Payload:           *flPayload,
		MTUSweep:          *flMTUSweep,
		TargetsPath:       *flTargets,
		ReloadInterval:    *flTargetsReload,
	}
	coverage, err := prober.ParseHMACCoverage(*flHMACCoverage)
	if err != nil {
		return prober.Config{}, err
	}
	cfg.HmacCoverage = coverage
	// Validate the whole config here so -svc=install and run() cannot accept
	// different configurations: both reach RunClient through this builder.
	// A self-only mesh file is diagnosed by resolveAllowlist with a more
	// specific message ("no peers to derive an allowlist from"), so leave
	// the empty target set to it rather than preempting with "no targets".
	if !(skipSelf && len(targets) == 0) {
		if err := cfg.Validate(); err != nil {
			return prober.Config{}, err
		}
	}
	return cfg, nil
}

// resolveMetricsAuth combines the CLI flags with the LINK_PING_METRICS_USER /
// LINK_PING_METRICS_PASS environment variables (flags win). Username and
// password must be configured as a pair: user-only would otherwise enable
// auth with an empty password.
func resolveMetricsAuth() (string, string, error) {
	userFlag, passFlag := *flMetricsBasicAuthUser, *flMetricsBasicAuthPass
	hasFlag := userFlag != "" || passFlag != ""
	var user, pass string
	if hasFlag {
		user, pass = userFlag, passFlag
	} else {
		user = os.Getenv("LINK_PING_METRICS_USER")
		pass = os.Getenv("LINK_PING_METRICS_PASS")
	}
	if (user == "") != (pass == "") {
		return "", "", errors.New("metrics basic auth requires both username and password (-metrics-user/-metrics-pass or LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS)")
	}
	// r.BasicAuth() splits the header at the FIRST colon, so a username
	// containing ':' can never be produced by a client: the part before
	// the colon is what must match. Accepting such a user here would make
	// the endpoint permanently unreachable (401 for every attempt).
	if strings.Contains(user, ":") {
		return "", "", errors.New("metrics basic auth username must not contain ':' (HTTP Basic Auth splits user:pass at the first colon, so this user is unreachable and every request 401s)")
	}
	return user, pass, nil
}

// startupFlags is the resolved form of the flags that must be validated before
// anything is bound (run) or registered (install).
type startupFlags struct {
	echoSecret, echoSecretOld string
	metricsUser, metricsPass  string
	metricsCert, metricsKey   string
}

// checkStartupFlags runs the mode/auth/TLS checks that must fail BEFORE a port
// is bound or an SCM entry is written. One helper, used by both run() and the
// -svc=install path, so install can never freeze a command line that run() will
// refuse: that mismatch produced an install that started cleanly and then
// exited 1 every five seconds from the SCM OnFailure ladder, with no log at all
// when -log-file was unset.
func checkStartupFlags() (startupFlags, error) {
	// A bad -mode should never open ports or start servers.
	switch mode := *flMode; mode {
	case "server", "client", "both":
	default:
		return startupFlags{}, fmt.Errorf("unknown mode: %s", mode)
	}

	// Rotation guard. ServePacketConn consults echoSecretOld only inside
	// its `if echoSecret != ""` branch (internal/prober/server.go), so an
	// old secret on its own authenticates NOTHING: with the primary secret
	// empty the agent runs unauthenticated while an operator mid-rotation
	// believes the rotation protection is active. Fail fast instead.
	sf := startupFlags{echoSecret: resolveEchoSecret(), echoSecretOld: resolveEchoSecretOld()}
	if sf.echoSecret == "" && sf.echoSecretOld != "" {
		return startupFlags{}, errors.New("-echo-secret-old is set without -echo-secret: the old secret alone provides no authentication (it is only accepted alongside a primary secret), so the agent would run unauthenticated; set -echo-secret or clear -echo-secret-old")
	}
	// Runs here (not in run()) so the ignored-flag warnings also reach an
	// operator at install time, when the persisted flags are still editable.
	warnIgnoredFlags(*flMode)

	user, pass, err := resolveMetricsAuth()
	if err != nil {
		return startupFlags{}, err
	}
	sf.metricsUser, sf.metricsPass = user, pass
	sf.metricsCert, sf.metricsKey = *flMetricsTLSCert, *flMetricsTLSKey
	if (sf.metricsCert == "") != (sf.metricsKey == "") {
		return startupFlags{}, errors.New("-metrics-tls-cert and -metrics-tls-key must be set together")
	}
	if sf.metricsCert != "" {
		// Validation only: the pair is loaded again by the listener, which
		// seeds its reload cache with it.
		// pi-lens-ignore: go-ignored-call-result
		if _, err := tls.LoadX509KeyPair(sf.metricsCert, sf.metricsKey); err != nil {
			return startupFlags{}, fmt.Errorf("metrics TLS: %w", err)
		}
	}
	if user != "" && sf.metricsCert == "" && !*flMetricsAllowInsecure {
		return startupFlags{}, errors.New("metrics basic auth requires TLS (-metrics-tls-cert/-key) or -metrics-allow-insecure to allow plaintext")
	}
	return sf, nil
}

// resolveAllowlist resolves the echo responder's fail-closed client allowlist:
// -allow plus, in mesh mode, the peer list derived from the targets file. Shared
// by run() and -svc=install so the two cannot accept different configurations.
func resolveAllowlist(mode string, cfg prober.Config) (*prober.Allowlist, error) {
	if mode == "client" {
		// Client mode has no echo responder. -allow's value is never parsed here:
		// parsing it made `-mode=client -allow=bogus` print the "-allow set but
		// ignored" warning and then exit 1 on the unparsable entry.
		return prober.ParseAllowlist("")
	}
	// The echo responder refuses to run without an explicit -allow list, so
	// spoofed/unauthorised sources can neither reflect datagrams nor grow
	// metric label cardinality. Mesh mode derives it from the targets file
	// instead: every peer the agent probes is allowed to probe it back, and the
	// self target was already dropped by buildConfig. -allow still contributes,
	// so a mesh can also allow extra CIDRs explicitly.
	allowSpec := *flAllow
	if meshAllowFromTargets() {
		if len(cfg.Targets) == 0 {
			// Server-only mode never loads the targets file, and a file that
			// lists only this site has no peers left after the self filter:
			// name that instead of falling through to the generic
			// "requires -allow" refusal, which hides why the flag had no
			// effect.
			return nil, errors.New("-allow-from-targets: no peers to derive an allowlist from (the targets file is empty or lists only this -source); run client/both with a mesh targets file, or pass -allow")
		}
		derived, err := prober.AllowEntriesFromTargets(cfg.Targets)
		if err != nil {
			return nil, err
		}
		if allowSpec == "" {
			allowSpec = derived
		} else {
			allowSpec = derived + "," + allowSpec
		}
	}
	allow, err := prober.ParseAllowlist(allowSpec)
	if err != nil {
		return nil, err
	}
	if (mode == "server" || mode == "both") && allow.Len() == 0 {
		return nil, errors.New("server mode requires -allow (comma-separated client IP allowlist); fail-closed")
	}
	return allow, nil
}

// serviceConfig returns the base Windows/SCM service configuration.
// Enterprise hardening baked in at install time:
//   - OnFailure restart (5s delay): a crash or non-zero exit is restarted
//     by the Service Control Manager instead of staying stopped forever.
//   - DelayedAutoStart: avoids racing network-stack availability at boot
//     (a metrics bind failure would otherwise be fatal with no recovery).
//   - Dependencies on Tcpip (sockets) and W32Time (the HMAC replay window
//     requires roughly NTP-synchronized clocks between nodes).
//
// The description deliberately omits the version string: it is frozen at
// install time and goes stale on in-place upgrades — runtime truth lives
// in the link_ping_build_info metric instead.
// serviceInstallSpec is the OS-neutral shape of the service hardening
// (portable so TestServiceConfigHardening pins it directly): nothing else
// declares SCM behavior anywhere in the binary.
type serviceInstallSpec struct {
	Name                string
	DisplayName         string
	Description         string
	Dependencies        []string
	DelayedAutoStart    bool
	RecoveryDelay       time.Duration
	RecoveryResetPeriod uint32
}

func serviceSpec() serviceInstallSpec {
	return serviceInstallSpec{
		Name:        "link_ping_prometheus",
		DisplayName: "Link Ping Prometheus",
		Description: "UDP echo link monitor: Prometheus latency, packet loss, and jitter metrics",
		Dependencies: []string{
			"Tcpip",
			"W32Time",
		},
		DelayedAutoStart:    true,
		RecoveryDelay:       5 * time.Second,
		RecoveryResetPeriod: 86400,
	}
}

// foregroundRun drives the plain signal-handling foreground run shared by
// `main()` and the non-SCM -svc=run paths (Windows console debugging and
// systemd/launchd on unix, which manage the process themselves).
func foregroundRun(prg *program) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	prg.ctx, prg.cancel = ctx, cancel
	return prg.run()
}

// absolutizeFlagValue returns the value to persist for a flag at service
// install time. Only the path flags are rewritten to absolute paths: the SCM
// starts the service with an unrelated working directory, so a relative path
// would resolve somewhere else at run time. Every other flag — notably the
// integer log-rotation flags log-file-max-mb/-backups/-age — is returned
// verbatim: absolutizing a bare number produced "C:\cwd\50", which made the
// service exit 2 at flag.Parse with stderr discarded under the SCM, i.e. an
// invisible crash loop.
func absolutizeFlagValue(name, value string) string {
	switch name {
	case "targets", "metrics-tls-cert", "metrics-tls-key", "log-file":
	default:
		return value
	}
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		// Unresolvable working directory: keep the value as given rather
		// than dropping the flag entirely.
		return value
	}
	return abs
}

// installServiceArgs validates the configuration -svc=install is about to
// freeze into the SCM command line, then returns that command line. Validation
// is not optional here: the flags are persisted and replayed on every service
// start, so a config run() refuses — the DEFAULT -mode=server with no -allow,
// say — installs "successfully" and then exits 1 on every start, which the SCM
// OnFailure ladder turns into a restart every 5 seconds forever, with no log at
// all when -log-file is unset. The checks are run()'s own, through the same
// helpers, so install and run cannot drift.
func installServiceArgs() ([]string, error) {
	// Both results are validation-only here; run() consumes the values.
	// pi-lens-ignore: go-ignored-call-result
	if _, err := checkStartupFlags(); err != nil {
		return nil, err
	}
	mode := *flMode
	var cfg prober.Config
	if mode != "server" {
		var err error
		if cfg, err = buildConfig(); err != nil {
			return nil, err
		}
	}
	// buildConfig validates the resolved source in client/both mode; server
	// mode never calls it, so validate the flag here too. -svc=install
	// -mode=server -source="Sydney DC" used to install and then exit 1 on
	// every SCM start. Validate it here whatever the mode.
	if cfg.Source == "" {
		if _, err := resolveSource(); err != nil {
			return nil, err
		}
	}
	// The bind addresses are the same crash loop when malformed (the persisted
	// flag can never bind), so resolve them here too. Resolution only — a bind
	// failure is the runtime's business.
	if _, err := net.ResolveTCPAddr("tcp", *flMetrics); err != nil {
		return nil, fmt.Errorf("invalid -metrics address: %w", err)
	}
	if mode == "server" || mode == "both" {
		if _, err := net.ResolveUDPAddr("udp", *flListen); err != nil {
			return nil, fmt.Errorf("invalid -listen address: %w", err)
		}
	}
	// pi-lens-ignore: go-ignored-call-result
	if _, err := resolveAllowlist(mode, cfg); err != nil {
		return nil, err
	}
	if *flTargets != "" && *flTargetsReload == 0 {
		// A Windows service has no SIGHUP, and -targets-reload-interval is the
		// only other reload trigger: without it the targets file is read once at
		// start and never again for the life of the process, so a peer edit
		// stays invisible until someone restarts the service.
		fmt.Println("WARNING: -targets is set but -targets-reload-interval is 0; a Windows service has no SIGHUP, so the targets file is read once at start and never re-read for the life of the process. Pass -targets-reload-interval (e.g. 1m) to pick up changes.")
	}
	// Build the SCM command line from the live flags at install time,
	// excluding -svc itself and the credential flags (-metrics-
	// user/-metrics-pass/-echo-secret/-echo-secret-old so credentials
	// are never persisted; they are delivered via env vars).
	var args []string
	flag.Visit(func(f *flag.Flag) {
		if f.Name != "svc" && f.Name != "metrics-user" && f.Name != "metrics-pass" && f.Name != "echo-secret" && f.Name != "echo-secret-old" {
			v := absolutizeFlagValue(f.Name, f.Value.String())
			args = append(args, fmt.Sprintf("-%s=%s", f.Name, v))
		}
	})
	args = append(args, "-svc=run")
	return args, nil
}

// handleService manages the service lifecycle. Install/uninstall are
// Windows-only (gated by svcActionSupported: Linux deploys use the static
// systemd unit via the Ansible play, and the Linux renderers flagged by
// supply-chain scanners are thereby unreachable). start/stop are
// cross-platform conveniences around native service control. The service
// run mode follows the windows_exporter pattern: x/sys/windows/svc under
// the SCM, plain signal-driven foreground everywhere else.
func handleService(action string, logSink *countedWriter) {
	if !svcActionSupported(action) {
		slog.Error("unsupported -svc action on this OS: install/uninstall are Windows-only (Linux deploys use the systemd unit in installer/linux)", "action", action, "os", runtime.GOOS)
		os.Exit(1)
	}

	prg := &program{logSink: logSink}

	switch action {
	case "install":
		// Validate first: nothing below may reach the SCM for a config the
		// runtime will refuse on every start (see installServiceArgs).
		args, err := installServiceArgs()
		if err != nil {
			slog.Error("Service install refused: the persisted configuration would fail at startup", "err", err)
			fmt.Fprintf(os.Stderr, "service install refused: %v\n", err)
			os.Exit(1)
		}
		if err := platformInstallService(args); err != nil {
			slog.Error("Service install failed", "err", err)
			os.Exit(1)
		}
		if *flMetricsBasicAuthUser != "" || *flMetricsBasicAuthPass != "" {
			fmt.Println("WARNING: -metrics-user/-metrics-pass are NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_METRICS_USER/LINK_PING_METRICS_PASS in the service environment instead.")
		}
		if *flEchoSecret != "" {
			fmt.Println("WARNING: -echo-secret is NOT persisted into the service configuration.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET in the service environment instead.")
		}
		if *flEchoSecretOld != "" {
			fmt.Println("WARNING: -echo-secret-old is NOT persisted into the service config.")
			fmt.Println("Configure LINK_PING_ECHO_SECRET_OLD in the service environment instead.")
		}
		if *flLogFile == "" {
			// stdout is discarded under the service: without -log-file every
			// slog line vanishes and a crash can be completely invisible.
			fmt.Println("WARNING: -log-file is not set; under the service stdout is discarded so NO logs will be captured anywhere.")
			fmt.Println("Pass -log-file=<path> at install time (lifecycle events still reach the Windows event log).")
		}
		fmt.Println("Service installed.")
	case "uninstall":
		if err := platformUninstallService(); err != nil {
			slog.Error("Service uninstall failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service uninstalled.")
	case "start":
		if err := platformStartService(); err != nil {
			slog.Error("Service start failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service started.")
	case "stop":
		if err := platformStopService(); err != nil {
			slog.Error("Service stop failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("Service stopped.")
	case "run":
		// The exit contract matters more than the return value: a run
		// error must leave the process unclean (non-zero) so the SCM
		// restart ladder fires - never a clean "handled" exit.
		if err := platformRunService(prg); err != nil {
			slog.Error("Service run error", "err", err)
			os.Exit(1)
		}
	default:
		// A typo like -svc=instal must not exit 0: the operator would
		// read that as "installed" and get no service and no error.
		slog.Error("Unknown action", "action", action)
		os.Exit(1)
	}
}

// program implements service.Interface for kardianos/service.
type program struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// svc is the lifecycle-event logger Start() received (nil");
	// anonymous foreground runs); the sink watcher writes log-sink
	// failures there so they reach the Windows event log even when the
	// log file itself is dead.
	svc eventlogSink
	// logSink wraps the -log-file writer (nil without -log-file) so
	// runtime write failures become visible; see logsink.go.
	logSink *countedWriter
	// testServeMetrics, when set (tests only), replaces startMetricsServer
	// in run(): the test owns the *http.Server handle so it can kill the
	// listener mid-run and observe the fatal path deterministically.
	// Production leaves it nil; nil selects the real binder.
	testServeMetrics func() (*http.Server, <-chan struct{}, error)
}

// Start is called by the service framework to begin execution.
// The WaitGroup Add happens here — before the goroutine starts — so
// Stop can never race it (the framework calls Stop only after Start
// has returned).
func (p *program) Start(sysLog eventlogSink) error {
	p.svc = sysLog
	// Lifecycle events go to the system logger (Windows event log under
	// the SCM): the only channel a fleet operator sees without access to
	// -log-file. Best-effort — file logging stays the primary sink.
	if sysLog != nil {
		sysLog.Info(fmt.Sprintf("link_ping_prometheus service starting (version %s)", version))
	}
	// pi-lens-ignore: go-context-background-handler
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.run(); err != nil {
			slog.Error("Service run error", "err", err)
			if sysLog := p.svc; sysLog != nil {
				sysLog.Error(fmt.Sprintf("service run failed: %v", err))
			}
			// Die UNCLEANLY: exiting non-zero classifies this as a failure
			// to the SCM so the OnFailure restart action fires. Calling
			// s.Stop() here would report a clean SERVICE_STOPPED and the
			// monitor would stay down until manual intervention.
			os.Exit(1)
		}
	}()
	return nil
}

// svcStopDeadline bounds program.Stop's drain wait. A var so the
// timeout-arm test does not need a real 20s stall.
var svcStopDeadline = 20 * time.Second

// serviceName is the service identity across platforms (SCM name, the
// event-log source, and the unit/labelctl label the unix adapters call).
const serviceName = "link_ping_prometheus"

// svcActionSupported reports whether the -svc lifecycle action is
// supported on the current OS. install/uninstall are Windows-only: the
// Linux install path would run the binary's own service renderers
// (systemd/openrc/... unit and init-script generation), which no
// supported deployment exercises - Linux installs use the static systemd
// unit shipped via the Ansible play - and embedding configuration values
// into generated shell/unit scripts is exactly the surface
// supply-chain scanners flag on the OpenRC renderer (reachable only via
// this action). Every other action (run via the framework, start/stop
// helpers) stays cross-platform.
func svcActionSupported(action string) bool {
	switch action {
	case "install", "uninstall":
		return runtime.GOOS == "windows"
	default:
		return true
	}
}

// Stop is called by the service framework to shut down gracefully. It
// cancels the context and waits for the run goroutine (plus a bounded
// straggler drain), returning nil even when the drain deadline is
// exceeded so the SCM classifies an operator stop as clean.
func (p *program) Stop(_ eventlogSink) error {
	if p.cancel != nil {
		p.cancel()
	}
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(svcStopDeadline):
		// The drain missed the deadline, but this is an OPERATOR-requested
		// stop, not a crash: returning an error makes kardianos report
		// STOPPED with a service-specific exit code, which the SCM counts
		// as a FAILURE and answers with the OnFailure restart ladder — the
		// service the operator just stopped comes back up mid-maintenance.
		// The process exits either way; clean-stop classification is the
		// honest one. (The os.Exit(1) path in Start is the deliberate
		// opposite: a genuine run failure WANTS the restart to fire.)
		slog.Error("Service stop deadline exceeded")
		return nil
	}
}

// startMetricsServer binds addr, wires the metrics/status/probe handlers
// and starts serving in a goroutine. It returns the server plus a channel
// closed when serving stops; the listener is bound here rather than
// lazily so a bind failure reaches the caller as an error and aborts
// startup. String arguments are captured values, not flag reads: the
// serve goroutine may outlive flag mutation by tests or shutdown code.
// metricsHandler builds the /metrics handler for the default gatherer.
func metricsHandler(gzip bool) http.Handler {
	return metricsHandlerFor(prometheus.DefaultGatherer, gzip)
}

// metricsHandlerFor builds the /metrics handler for an arbitrary gatherer.
// gzip=false disables response compression on purpose: promhttp pools a
// gzip.Writer per P and each writer holds a flate compressor of roughly 0.7MB
// (hashHead 1<<17 + hashPrev 1<<15 plus a 32KB window), so compression costs up
// to ~0.7MB x GOMAXPROCS of live heap that only a GC reclaims - measured as the
// dominant scrape-driven heap growth. For a small fleet the whole response is
// smaller than one compressor, so plain is the lighter default; large fleets
// should enable it. The gatherer is a parameter so the concurrency cap it
// applies (MaxRequestsInFlight) can be exercised deterministically in tests.
func metricsHandlerFor(g prometheus.Gatherer, gzip bool) http.Handler {
	h := promhttp.HandlerFor(g, promhttp.HandlerOpts{
		DisableCompression:  !gzip,
		MaxRequestsInFlight: maxConcurrentScrapes,
	})
	// Restore the scrape instrumentation that promhttp.Handler() used to
	// register and HandlerFor() does not: without
	// promhttp_metric_handler_requests_total{code="503"} and
	// _requests_in_flight, a scrape rejected by the concurrency cap above is
	// invisible. Safe to call on every handler build (tests, repeated
	// registrations): it reuses the already-registered collector instead of
	// panicking.
	return promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, h)
}

// svcTraceMarker records a service-path diagnostic (windows e2e triage aid
// under the SCM where stderr is dead). It emits through slog at Debug so the
// configured handler owns the format: the previous raw "svc-trace[...]" line
// written straight into -log-file broke -json-logs parsing (the file is then a
// mix of JSON records and bare text) on every foreground run too. Only the
// -svc paths emit at all; a plain foreground run has no service to trace. The
// marker text is what the Windows e2e triage reads out of the log, so keep the
// "svc-trace[...]" shape in the message.
func svcTraceMarker(tag string) {
	if *flSvc == "" {
		return
	}
	slog.Debug(fmt.Sprintf("svc-trace[%s]", tag))
}

// readyToProbe reports whether a running agent can actually do its job, i.e.
// /readyz's notion of readiness as opposed to /healthz's liveness.
// SocketAgeSeconds is nonzero only while the target currently holds a socket:
// the dial-retry path publishes 0 and a failed re-dial resets it, so this is
// "can probe right now", not "has ever probed". An agent stuck resolving DNS or
// blocked by a firewall is alive but useless, and an orchestrator must see that.
// Reads the registry in place (see StatusRegistry.AnyReady) rather than
// snapshotting it: /readyz is unauthenticated and uncapped.
func readyToProbe(mode string, statusReg *prober.StatusRegistry) bool {
	if mode == "server" {
		// Server-only mode has no targets at all, and a server that cannot
		// bind dies instead of limping, so it is ready by definition.
		return true
	}
	return statusReg.AnyReady()
}

// readinessHandler answers /readyz: 200 when probing is possible, 503 when a
// client-side agent has never held a working socket for any target.
func readinessHandler(mode string, statusReg *prober.StatusRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !readyToProbe(mode, statusReg) {
			w.WriteHeader(http.StatusServiceUnavailable)
			// pi-lens-ignore: go-ignored-call-result
			_, _ = w.Write([]byte("not ready: no target has ever had a working socket\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		// pi-lens-ignore: go-ignored-call-result
		_, _ = w.Write([]byte("ok\n"))
	})
}

// limitConcurrent wraps handler in a counting semaphore of limit slots:
// the first limit concurrent requests are served normally, any further
// request gets a plain-text 503 (the same status and message shape the
// /metrics cap produces) and never reaches the handler. Slot release is
// tied to the ServeHTTP call itself (not to the handler's return), so a
// panic among the admitted requests unwinds through the deferred release
// and cannot leak a slot forever. The semaphore is a channel, exactly
// the promhttp MaxRequestsInFlight pattern, which /status cannot reuse
// because it is bound to a Gatherer rather than a plain handler.
func limitConcurrent(limit int, handler http.Handler) http.Handler {
	sem := make(chan struct{}, limit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			handler.ServeHTTP(w, r)
		default:
			// Same wording shape as promhttp's MaxRequestsInFlight body; the
			// limit is interpolated, not hardcoded, so the body cannot drift
			// from the cap a maintainer changes.
			http.Error(w, fmt.Sprintf("Limit of concurrent requests reached (%d), try again later.", limit), http.StatusServiceUnavailable)
		}
	})
}

// certReloadRetryCooldown is how long a fingerprint whose load FAILED is
// skipped before the pair is read again. The retry is what makes an in-place
// repair observable: a pair fixed without touching (mtime, size) — a
// chmod-only fix, a same-size rewrite that preserves the timestamp — keeps the
// fingerprint the failed attempt was recorded under, so a pure memo would serve
// the expired certificate until the files changed again, i.e. exactly the
// silent scrape blackout the reloader exists to prevent. The cooldown keeps the
// other side of that tradeoff: a genuinely broken renewal costs one file read
// (and at most one Warn) per cooldown, not one per handshake. A var so tests
// can lower it.
var certReloadRetryCooldown = 30 * time.Second

// metricsCertReloader serves the metrics TLS pair from a cache that is re-read
// when either file's (mtime, size) changes, so a renewed certificate takes
// effect without a restart. ServeTLS otherwise loads the pair exactly once: on
// 90-day certificates plus a service that is never restarted, that one-shot load
// is a silent scrape blackout the day the cert expires — and under the SCM the
// resulting handshake error is invisible (stderr is discarded). Set as
// TLSConfig.GetCertificate, which crypto/tls consults for every handshake.
type metricsCertReloader struct {
	certPath, keyPath string

	mu sync.Mutex
	// cert is the pair currently served. Seeded at construction, so no
	// handshake can ever observe an empty cache.
	cert *tls.Certificate
	// loaded is the fingerprint of the pair in cert; attempted/attemptedAt are
	// the last fingerprint a reload was tried for and when. Kept apart so a
	// failed load is retried only after certReloadRetryCooldown rather than on
	// every handshake, which would flood the very log the reload exists to make
	// visible (see certReloadRetryCooldown for why the retry matters at all).
	loaded, attempted certFingerprint
	attemptedAt       time.Time
	// statFailed latches the stat-error warning the same way.
	statFailed bool
}

// certFingerprint identifies a certificate/key file pair by the metadata a
// renewal changes. Hashing the contents would cost a full read on every
// handshake; (mtime, size) is what rotators and `mv` in place actually touch.
type certFingerprint struct {
	certMod, keyMod   time.Time
	certSize, keySize int64
}

func fingerprintCertPair(certPath, keyPath string) (certFingerprint, error) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return certFingerprint{}, err
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return certFingerprint{}, err
	}
	return certFingerprint{
		certMod: certInfo.ModTime(), certSize: certInfo.Size(),
		keyMod: keyInfo.ModTime(), keySize: keyInfo.Size(),
	}, nil
}

// newMetricsCertReloader loads the pair once and seeds the cache with it — the
// same load run() performs as startup validation. A pair that will not load is
// a startup error, never a listener that serves nothing.
func newMetricsCertReloader(certPath, keyPath string) (*metricsCertReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	fp, err := fingerprintCertPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &metricsCertReloader{certPath: certPath, keyPath: keyPath, cert: &cert, loaded: fp, attempted: fp}, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *metricsCertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fp, err := fingerprintCertPair(r.certPath, r.keyPath)
	if err != nil {
		// Unstattable (a rename-in-progress, a rotated-away inode): keep serving
		// the cached pair rather than failing every handshake on the way past.
		if !r.statFailed {
			r.statFailed = true
			slog.Warn("Metrics TLS certificate files are not statable; keeping the previously loaded certificate",
				"cert", r.certPath, "key", r.keyPath, "err", err)
		}
		return r.cert, nil
	}
	r.statFailed = false
	if fp == r.loaded {
		return r.cert, nil
	}
	if fp == r.attempted && time.Since(r.attemptedAt) < certReloadRetryCooldown {
		return r.cert, nil
	}
	r.attempted, r.attemptedAt = fp, time.Now()
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		// A half-written renewal or a key that does not match: keep the working
		// cert and say so once. Failing the handshake instead would black out
		// every scrape over a transient write.
		slog.Warn("Metrics TLS certificate reload failed; keeping the previously loaded certificate",
			"cert", r.certPath, "key", r.keyPath, "err", err)
		return r.cert, nil
	}
	r.cert, r.loaded = &cert, fp
	slog.Info("Metrics TLS certificate reloaded", "cert", r.certPath, "key", r.keyPath)
	return r.cert, nil
}

// warnUnauthenticatedMetricsBind warns when the metrics listener came up on an
// address reachable from off-host with no Basic auth. The flag help says the
// default binds localhost only, but nothing at runtime says the operator just
// widened it without credentials — and the payload is the probe topology, peer
// IPs and per-link RTT/loss, i.e. the network map itself.
func warnUnauthenticatedMetricsBind(addr net.Addr, user string) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || user != "" || tcpAddr.IP.IsLoopback() {
		return
	}
	slog.Warn("Metrics endpoint is bound to a non-loopback address WITHOUT authentication: anyone who can reach it sees the probe topology, peer IPs and per-link RTT/loss",
		"addr", tcpAddr.String(),
		"fix", "bind 127.0.0.1, or set -metrics-user/-metrics-pass with -metrics-tls-cert/-metrics-tls-key (or -metrics-allow-insecure to accept plaintext auth)")
}

func (p *program) startMetricsServer(addr, user, pass, cert, key string, statusReg *prober.StatusRegistry, gzip bool, mode string) (*http.Server, <-chan struct{}, error) {
	// Resolve the TLS pair BEFORE binding: a cert that cannot be loaded must
	// abort startup without leaving a bound port behind it.
	var tlsCfg *tls.Config
	if cert != "" {
		reloader, err := newMetricsCertReloader(cert, key)
		if err != nil {
			return nil, nil, fmt.Errorf("metrics TLS: %w", err)
		}
		// GetCertificate (not the Certificates slice) so every handshake can pick
		// up a renewed pair. Constructing the reloader here is also the startup
		// validation: a pair that will not load aborts the bind attempt.
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: reloader.GetCertificate}
	}
	metricsLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("metrics server: %w", err)
	}
	warnUnauthenticatedMetricsBind(metricsLn.Addr(), user)
	mx := http.NewServeMux()
	mx.Handle("/metrics", prober.MetricsAuth(user, pass, metricsHandler(gzip)))
	healthzHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// pi-lens-ignore: go-ignored-call-result
		_, _ = w.Write([]byte("ok\n"))
	})
	// /healthz and /readyz are deliberately unauthenticated: they are
	// liveness/readiness probes that an orchestrator must reach without
	// credentials, and they expose no data. Do not gate them. /readyz is NOT
	// an alias of /healthz (it was): liveness means the process is running,
	// readiness means it is actually probing.
	mx.Handle("/healthz", healthzHandler)
	mx.Handle("/readyz", readinessHandler(mode, statusReg))
	// /status exposes live per-target probe state (link_up, inflight,
	// misses, RTO, socket age). Gated like /metrics: open only when no
	// metrics auth is configured. Capped like /metrics too: the snapshot
	// copies and sorts the whole registry and the process snapshot does a
	// potentially STW ReadMemStats, so a local burst loop must not pile
	// those on top of each other. /healthz and /readyz stay uncapped —
	// they are cheap booleans an orchestrator must always reach.
	mx.Handle("/status", prober.MetricsAuth(user, pass, limitConcurrent(maxConcurrentScrapes, statusReg.Handler())))
	metricsSrv := &http.Server{
		Handler: mx,
		// net/http reports its OWN failures (TLS handshake errors, accept
		// errors, recovered handler panics) through the std log package to
		// os.Stderr — and under the Windows service stderr is discarded, so a
		// failing handshake or a panicking handler would leave no trace at all.
		// Route them through slog so they land in -log-file / the event log
		// with everything else.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
		// Addr is informational (Serve uses the already-bound listener) but
		// lets tests and logs address the live server without guessing.
		Addr:        metricsLn.Addr().String(),
		ReadTimeout: 10 * time.Second,
		// 30s, not 10s: a large fleet on a slow link can need longer than 10s
		// to write a multi-megabyte scrape body, and a truncated response
		// reads as the monitor itself being down. Reads stay at 10s so a slow
		// client still cannot hold a connection.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// Bounded header read: ReadTimeout alone starts only after the
		// headers land, so a slowloris client could otherwise hold a
		// connection open indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
	}
	if tlsCfg != nil {
		metricsSrv.TLSConfig = tlsCfg
	}
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		slog.Info("Starting metrics server", "addr", addr, "tls", cert != "", "auth", user != "")
		var serveErr error
		if tlsCfg == nil {
			serveErr = metricsSrv.Serve(metricsLn)
		} else {
			// Empty cert/key paths on purpose: ServeTLS only skips its own
			// tls.LoadX509KeyPair when the config already carries a certificate
			// source, and it is the pair loaded into TLSConfig.Certificates that
			// would freeze the renewal. crypto/tls consults GetCertificate only
			// while that slice is empty (or the client sent SNI), so a scraper
			// dialing an IP literal would otherwise keep being served the startup
			// copy. ServeTLS (unlike a hand-rolled tls.NewListener) still owns the
			// HTTP/2 ALPN setup. The reloader already loaded and validated the
			// pair when it was constructed.
			serveErr = metricsSrv.ServeTLS(metricsLn, "", "")
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("Metrics server error", "err", serveErr)
		}
	}()
	return metricsSrv, metricsDone, nil
}

// run initialises metrics, starts the Prometheus HTTP server, and
// dispatches to the selected mode (server, client, or both).
func (p *program) run() error {
	prober.InitMetrics()
	prober.BuildInfo.WithLabelValues(version).Set(1)
	slog.Info("starting", "version", version)

	// Fail fast on unknown mode BEFORE binding anything: a bad -mode
	// should never open ports or start servers.
	sf, err := checkStartupFlags()
	if err != nil {
		return err
	}
	echoSecret, echoSecretOld := sf.echoSecret, sf.echoSecretOld
	user, pass, cert, key := sf.metricsUser, sf.metricsPass, sf.metricsCert, sf.metricsKey
	if user != "" && cert == "" {
		slog.Warn("Metrics basic auth over plaintext HTTP: credentials are base64-only on the wire; consider -metrics-tls-cert/-metrics-tls-key")
	}

	var cfg prober.Config
	if *flMode != "server" {
		var err error
		cfg, err = buildConfig()
		if err != nil {
			return err
		}
	}
	// Periodic scavenger: shares p.ctx so it stops with the mode loops.
	startHeapScavenger(p.ctx, *flMemScavenge, minScavengeUnreleased, slog.Default())

	// Log-durability watchers (see logsink.go / logacl_windows.go): sink
	// write failures surfaced outside the dead sink, and — Windows only —
	// a periodic idempotent re-apply of the restricted DACL, which a
	// lumberjack rotation silently regresses when the fresh live file
	// inherits a wide directory DACL. Both stop with p.ctx in every mode.
	watchLogSink(p.ctx, p.svc, p.logSink, sinkCheckInterval)
	startLogDACLRecheck(p.ctx, *flLogFile)

	// Live per-target state for the /status debug endpoint. Always
	// registered so server-only mode still serves an empty list.
	statusReg := prober.NewStatusRegistry()
	cfg.Status = statusReg
	// SIGHUP hot-reload of the targets file (Unix; Windows services use
	// -targets-reload-interval). Signals coalesce: every delivery just
	// re-reads and re-validates the file, which is idempotent.
	if *flTargets != "" {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP)
		defer signal.Stop(sigCh)
		cfg.ReloadSignal = sigCh
	}

	// Resolve source for server metrics. buildConfig already validated it in
	// client/both mode (and set cfg.Source); server-only mode skips
	// buildConfig, so resolve and validate it here through the same helper.
	sourceForServer := cfg.Source
	if sourceForServer == "" {
		var err error
		sourceForServer, err = resolveSource()
		if err != nil {
			return err
		}
	}

	// Fail-closed client allowlist, resolved by the same helper -svc=install
	// validates against (see resolveAllowlist).
	allow, err := resolveAllowlist(*flMode, cfg)
	if err != nil {
		return err
	}

	// Bind the metrics listener before any probing starts so a bind
	// failure (port taken, permission denied) aborts startup instead of
	// leaving the agent running with no /metrics endpoint — a silent
	// partial failure for a monitoring agent.
	startMetrics := p.testServeMetrics
	if startMetrics == nil {
		startMetrics = func() (*http.Server, <-chan struct{}, error) {
			return p.startMetricsServer(*flMetrics, user, pass, cert, key, statusReg, *flMetricsGzip, *flMode)
		}
	}
	metricsSrv, metricsDone, err := startMetrics()
	if err != nil {
		return err
	}

	// echoSecret/echoSecretOld resolved at the top of run(): the rotation
	// guard must fire before any bind, not after the metrics server is up.
	mode := *flMode
	// runCtx: a mid-run metrics-serve failure must cancel the mode loops.
	// A monitor without a live /metrics endpoint is dead weight that looks
	// healthy — probes continue, the SCM/OS-level process is "running", and
	// nothing restarts until manual intervention. The serve goroutine runs
	// until Serve returns; any return other than deliberate Shutdown closes
	// metricsDone, which is fatal below.
	runCtx, runCancel := context.WithCancel(p.ctx)
	defer runCancel()
	modeDone := make(chan error, 1)
	go func() { modeDone <- runModes(runCtx, mode, cfg, sourceForServer, allow, echoSecret, echoSecretOld) }()
	var modeErr error
	select {
	case modeErr = <-modeDone:
	case <-metricsDone:
		// The serve goroutine returned before Shutdown: the listener or an
		// accept failed mid-run. Cancel the mode loops and fail the run so
		// the agent exits non-zero and service recovery can fire, instead of
		// probing without an endpoint for the remaining uptime.
		runCancel()
		<-modeDone
		modeErr = errors.New("metrics server terminated unexpectedly; monitor cannot serve metrics, status, or health endpoints")
	}
	// Drain the metrics server on the way out so an in-flight scrape
	// finishes instead of being cut off by process exit. On the
	// metricsDone path the server is already gone and Shutdown is a no-op;
	// on a normal mode exit it stops the listener and unblocks the select's
	// second case only if it had not fired yet.
	// pi-lens-ignore: go-context-background-handler
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// pi-lens-ignore: go-ignored-call-result
	_ = metricsSrv.Shutdown(shutCtx)
	// Bounded join: a scrape mid-write holds Serve open up to the 30s
	// WriteTimeout, which exceeds the service Stop deadline (20s) - waiting
	// unconditionally would make Stop report "timed out" while the process
	// was still draining a clean shutdown. The drain is best-effort (the
	// agent's own metrics die with the process), so after the Shutdown
	// deadline a short grace is all an in-flight scrape gets.
	select {
	case <-metricsDone:
	case <-time.After(shutdownJoinGrace):
		slog.Warn("metrics server drain grace exceeded; continuing exit", "grace", shutdownJoinGrace)
	}
	return modeErr
}

// runModes executes the selected probe/server mode until ctx is cancelled,
// returning its terminal error. Extracted from run() so the metrics-server
// death at the select above is comparable to (and can preempt) a mode exit.
func runModes(
	ctx context.Context,
	mode string,
	cfg prober.Config,
	sourceForServer string,
	allow *prober.Allowlist,
	echoSecret string,
	echoSecretOld string,
) error {
	switch mode {
	case "server":
		return prober.RunServer(ctx, *flListen, sourceForServer, allow, echoSecret, echoSecretOld)
	case "client":
		return prober.RunClient(ctx, cfg)
	case "both":
		// Local WaitGroup: Add is sequenced before the goroutine starts
		// and Wait runs in the same goroutine, so no Add/Wait race.
		modeCtx, modeCancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		var serverErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := prober.RunServer(modeCtx, *flListen, sourceForServer, allow, echoSecret, echoSecretOld); err != nil {
				// A server that fails to start (e.g. port already in
				// use) is fatal in both mode: cancelling the client too
				// fails fast instead of probing silently without an
				// echo responder.
				serverErr = err
				modeCancel()
			}
		}()
		clientErr := prober.RunClient(modeCtx, cfg)
		modeCancel()
		wg.Wait()
		if serverErr != nil {
			return serverErr
		}
		return clientErr
	default:
		return fmt.Errorf("unknown mode: %s", mode)
	}
}
