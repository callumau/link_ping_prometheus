package config

import (
	"errors"
	"flag"
	"fmt"
	"time"
)

// Flags holds the CLI flag pointers registered on a FlagSet.
type Flags struct {
	Mode                 *string
	Listen               *string
	Allow                *string
	AllowFromTargets     *bool
	Target               *string
	Targets              *string
	Metrics              *string
	Svc                  *string
	JSONLogs             *bool
	LogFile              *string
	LogMaxSize           *int
	LogMaxBackups        *int
	LogMaxAge            *int
	Adaptive             *bool
	BaseInterval         *time.Duration
	BaseTimeout          *time.Duration
	ReconnectInterval    *time.Duration
	Source               *string
	DSCP                 *int
	Payload              *int
	TargetsReload        *time.Duration
	MTUSweep             *time.Duration
	MemScavenge          *time.Duration
	MetricsBasicAuthUser *string
	MetricsBasicAuthPass *string
	MetricsTLSCert       *string
	MetricsTLSKey        *string
	MetricsAllowInsecure *bool
	MetricsGzip          *bool
	EchoSecret           *string
	EchoSecretOld        *string
	HMACCoverage         *string
}

// Register binds every CLI flag onto fs and returns the populated pointers.
func Register(fs *flag.FlagSet) *Flags {
	return &Flags{
		Mode:                 fs.String("mode", "server", "Mode: server, client, both"),
		Listen:               fs.String("listen", ":4000", "Server: Listen address"),
		Allow:                fs.String("allow", "", "Server: Comma-separated client IP allowlist (fail-closed: required in server/both mode)"),
		AllowFromTargets:     fs.Bool("allow-from-targets", false, "Server: derive the fail-closed allowlist from the -targets file addresses and skip the target whose name matches -source, so one targets file serves every site of a mesh (client/both mode; every target address must be an IP literal - a DNS name is an error, because config load never resolves). Combines with -allow for extra CIDRs."),
		Target:               fs.String("target", "", "Client: Single target address"),
		Targets:              fs.String("targets", "", "Client: JSON file path with targets"),
		Metrics:              fs.String("metrics", "127.0.0.1:2112", "Metrics: Listen address (default binds localhost only; use \":2112\" or \"0.0.0.0:2112\" to expose on all interfaces)"),
		Svc:                  fs.String("svc", "", "Service: install, uninstall (Windows only; Linux uses the systemd unit), start, stop, run"),
		JSONLogs:             fs.Bool("json-logs", false, "Log in JSON format"),
		LogFile:              fs.String("log-file", "", "Log: append logs to this file in addition to stdout (stdout is discarded under the Windows service)"),
		LogMaxSize:           fs.Int("log-file-max-mb", 10, "Log: max size in MB before rotation (0 disables rotation; requires -log-file)"),
		LogMaxBackups:        fs.Int("log-file-max-backups", 5, "Log: max rotated files to keep (requires -log-file)"),
		LogMaxAge:            fs.Int("log-file-max-age", 28, "Log: max days to keep rotated files (requires -log-file)"),
		Adaptive:             fs.Bool("adaptive", true, "Client: Use adaptive timeout based on link quality (RFC 6298)"),
		BaseInterval:         fs.Duration("interval", 500*time.Millisecond, "Client: Probe interval"),
		BaseTimeout:          fs.Duration("timeout", 1*time.Second, "Client: Base/Initial timeout"),
		ReconnectInterval:    fs.Duration("reconnect-interval", 5*time.Minute, "Client: How long to keep a UDP socket before re-dialing for DNS re-resolution (0 means global default 5m; use a large value e.g. 24h to effectively disable)"),
		Source:               fs.String("source", "", "Source label applied to all metrics, e.g. local datacenter (sydney-dc) (defaults to hostname)"),
		DSCP:                 fs.Int("dscp", 0, "Client: DSCP value 0-63 marked on probe packets (0 = no marking, default; e.g. 46 = EF). Best effort, requires OS support (Linux)"),
		Payload:              fs.Int("payload", 0, "Client: probe payload bytes beyond the 24/32-byte header (up to 1400), filled with a deterministic pattern and validated on echo; corruption is counted in link_probes_corrupted_total, distinct from loss"),
		TargetsReload:        fs.Duration("targets-reload-interval", 0, "Client: poll the -targets file at this interval and apply changes without a restart (0 disables; SIGHUP also reloads on Unix; Windows services need this flag to reload)"),
		MTUSweep:             fs.Duration("mtu-sweep", time.Minute, "Client: periodically sweep DF-set probe sizes per target to find the largest frame the path carries (0 disables; Linux, or Windows with IPv4 on 2003+ / IPv6 on 1703+; results in link_path_mtu_bytes and /status; separate counters, never in the loss ratio)"),
		MemScavenge:          fs.Duration("mem-scavenge", 5*time.Minute, "Process: force a heap scavenge at this interval so the unused heap high-water mark is returned to the OS (0 disables; the interval must be at least 100ms, because each scavenge stops the world). Scrapes ratchet the heap high-water up and the runtime does not return it while the agent is otherwise idle; on Windows that reads as RSS/commit growth."),
		MetricsBasicAuthUser: fs.String("metrics-user", "", "Metrics: Basic auth username (empty disables auth; env LINK_PING_METRICS_USER)"),
		MetricsBasicAuthPass: fs.String("metrics-pass", "", "Metrics: Basic auth password (env LINK_PING_METRICS_PASS; prefer env over CLI to avoid ps exposure)"),
		MetricsTLSCert:       fs.String("metrics-tls-cert", "", "Metrics: TLS certificate file (requires -metrics-tls-key)"),
		MetricsTLSKey:        fs.String("metrics-tls-key", "", "Metrics: TLS private key file (requires -metrics-tls-cert)"),
		MetricsAllowInsecure: fs.Bool("metrics-allow-insecure", false, "Metrics: allow Basic Auth over plaintext HTTP (otherwise requires TLS when auth is set)"),
		MetricsGzip:          fs.Bool("metrics-gzip", false, "Metrics: gzip-compress /metrics responses when the scraper offers it. Off by default: promhttp pools a gzip writer per CPU, and each holds ~0.7MB of flate state, so compression costs up to ~0.7MB x GOMAXPROCS of live heap - more than a small fleet's whole response. Enable it for many targets, where the response size matters."),
		EchoSecret:           fs.String("echo-secret", "", "Wire: HMAC secret for UDP echo authentication (env LINK_PING_ECHO_SECRET; mitigates reflector spoof when set on both client and server)"),
		EchoSecretOld:        fs.String("echo-secret-old", "", "Wire: previous HMAC secret, still accepted by the SERVER during a zero-downtime rotation alongside -echo-secret (env LINK_PING_ECHO_SECRET_OLD; server side only)"),
		HMACCoverage:         fs.String("hmac-coverage", "full-frame", "Wire: which frame bytes the client's HMAC tag covers when -echo-secret is set: 'full-frame' (default: header plus the -payload bytes, so a tampered payload or a payload riding a captured tag no longer authenticates; needs -payload > 0 to differ) or 'header' (the 24-byte header only — the v0.7 layout, byte-identical wire output; the escape hatch for probing through a v0.7 echo server while using -payload). The server side accepts both coverages whenever it has -echo-secret, so upgrading to ≥ v0.8 clears the one broken pairing (v0.7 server + full-frame client = payload probes read as loss)."),
	}
}

// Default registers all CLI flags on flag.CommandLine on package import.
var Default = Register(flag.CommandLine)

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

// SetFlagNamesForTest replaces setFlagNames for the duration of a test and
// returns a function that restores the previous value.
func SetFlagNamesForTest(fn func() []string) (restore func()) {
	orig := setFlagNames
	setFlagNames = fn
	return func() { setFlagNames = orig }
}

// SnapshotFlagsForTest saves all Default flag values and returns a function
// that restores them.
func SnapshotFlagsForTest() func() {
	d := Default
	old := struct {
		mode, listen, allow, target, targets, metrics, svc, logFile, source string
		user, pass, cert, key, echoSecret, echoSecretOld, hmacCoverage    string
		allowFromTargets, jsonLogs, adaptive, allowInsecure, gzip         bool
		logMaxSize, logMaxBackups, logMaxAge, dscp, payload               int
		baseInterval, baseTimeout, reconnect, reload, mtuSweep, scavenge  time.Duration
	}{
		mode: *d.Mode, listen: *d.Listen, allow: *d.Allow,
		target: *d.Target, targets: *d.Targets, metrics: *d.Metrics,
		svc: *d.Svc, logFile: *d.LogFile, source: *d.Source,
		user: *d.MetricsBasicAuthUser, pass: *d.MetricsBasicAuthPass,
		cert: *d.MetricsTLSCert, key: *d.MetricsTLSKey,
		echoSecret: *d.EchoSecret, echoSecretOld: *d.EchoSecretOld,
		hmacCoverage:     *d.HMACCoverage,
		allowFromTargets: *d.AllowFromTargets, jsonLogs: *d.JSONLogs,
		adaptive: *d.Adaptive, allowInsecure: *d.MetricsAllowInsecure, gzip: *d.MetricsGzip,
		logMaxSize: *d.LogMaxSize, logMaxBackups: *d.LogMaxBackups, logMaxAge: *d.LogMaxAge,
		dscp: *d.DSCP, payload: *d.Payload,
		baseInterval: *d.BaseInterval, baseTimeout: *d.BaseTimeout,
		reconnect: *d.ReconnectInterval, reload: *d.TargetsReload,
		mtuSweep: *d.MTUSweep, scavenge: *d.MemScavenge,
	}
	return func() {
		*d.Mode, *d.Listen, *d.Allow = old.mode, old.listen, old.allow
		*d.Target, *d.Targets, *d.Metrics = old.target, old.targets, old.metrics
		*d.Svc, *d.LogFile, *d.Source = old.svc, old.logFile, old.source
		*d.MetricsBasicAuthUser, *d.MetricsBasicAuthPass = old.user, old.pass
		*d.MetricsTLSCert, *d.MetricsTLSKey = old.cert, old.key
		*d.EchoSecret, *d.EchoSecretOld = old.echoSecret, old.echoSecretOld
		*d.HMACCoverage = old.hmacCoverage
		*d.AllowFromTargets, *d.JSONLogs = old.allowFromTargets, old.jsonLogs
		*d.Adaptive, *d.MetricsAllowInsecure, *d.MetricsGzip = old.adaptive, old.allowInsecure, old.gzip
		*d.LogMaxSize, *d.LogMaxBackups, *d.LogMaxAge = old.logMaxSize, old.logMaxBackups, old.logMaxAge
		*d.DSCP, *d.Payload = old.dscp, old.payload
		*d.BaseInterval, *d.BaseTimeout = old.baseInterval, old.baseTimeout
		*d.ReconnectInterval, *d.TargetsReload = old.reconnect, old.reload
		*d.MTUSweep, *d.MemScavenge = old.mtuSweep, old.scavenge
	}
}

// FlagWasSet reports whether the named flag was explicitly set on the
// command line (or via flag.Set). Use it instead of comparing a value against
// flag.Lookup(name).DefValue: a value comparison cannot distinguish "not set"
// from "explicitly set to the default".
func FlagWasSet(name string) bool {
	for _, n := range setFlagNames() {
		if n == name {
			return true
		}
	}
	return false
}

// ValidateLogRotationFlags rejects rotation flags without -log-file. Under
// the SCM stdout is discarded, so a service installed with a rotation flag
// but no -log-file would rotate nothing and have no log at all; that is a
// startup error, not a warning. Explicitly passing a default value counts as
// "set": the operator asked for a rotation policy, not the default one.
func ValidateLogRotationFlags() error {
	if *Default.LogFile != "" {
		return nil
	}
	if FlagWasSet("log-file-max-mb") || FlagWasSet("log-file-max-backups") || FlagWasSet("log-file-max-age") {
		return errors.New("log rotation flags require -log-file")
	}
	return nil
}

// MinScavengeInterval is the smallest accepted -mem-scavenge interval. Every
// tick is a stop-the-world runtime.ReadMemStats plus, above the releasable
// threshold, a debug.FreeOSMemory, in a process whose whole job is measuring
// RTT — a 1ms interval turns the latency it exports into GC pauses. Rejected at
// the flag boundary rather than clamped inside startHeapScavenger, so the
// scavenger loop stays a pure primitive its own test drives directly.
const MinScavengeInterval = 100 * time.Millisecond

// ValidateScavengeInterval enforces the -mem-scavenge floor (see
// MinScavengeInterval). 0 keeps meaning "disabled"; only a nonzero interval
// below the floor is refused.
func ValidateScavengeInterval(every time.Duration) error {
	if every < 0 {
		// Only 0 means "disabled" in the flag documentation; a negative
		// interval used to be silently accepted and disabled the scavenger,
		// so a typo read as a working configuration.
		return fmt.Errorf("-mem-scavenge %v is negative: use 0 to disable or an interval >= %v", every, MinScavengeInterval)
	}
	if every == 0 || every >= MinScavengeInterval {
		return nil
	}
	return fmt.Errorf("-mem-scavenge %v is too small: each scavenge is a stop-the-world runtime.ReadMemStats (plus debug.FreeOSMemory above the releasable threshold), so an interval this small would distort the RTT/loss this agent exists to measure; use 0 to disable or a value >= %v", every, MinScavengeInterval)
}
