package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"link_ping_prometheus/internal/prober"
	"log/slog"
	"os"
	"slices"
	"strings"
)

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
	// set-flag seam: a client run with the default must not warn.
	if *flAllow != "" && mode == "client" {
		slog.Warn("-allow set but ignored: the client allowlist only applies to the echo server (server/both mode)")
	}
	if *flAllowFromTargets && mode == "client" {
		slog.Warn("-allow-from-targets set but ignored: the derived allowlist and self-skip only apply to the echo server (server/both mode)")
	}
	if flagWasSet("listen") && mode == "client" {
		slog.Warn("-listen set but ignored: the listen address only applies to the echo server (server/both mode)")
	}
	if *flTargets != "" && *flTarget != "" && mode != "server" {
		slog.Warn("-targets and -target are both set: -targets wins, -target is ignored")
	}
	// -hmac-coverage shapes the tag the CLIENT writes; the echo server
	// accepts both coverages whenever -echo-secret is set, so the flag has
	// no effect in server-only mode.
	if flagWasSet("hmac-coverage") && mode == "server" {
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
// snapshotting it: /readyz is unauthenticated and uncapped.
