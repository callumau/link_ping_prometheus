package config

import (
	"errors"
	"fmt"
	"link_ping_prometheus/internal/httpserver"
	"link_ping_prometheus/internal/prober"
	"log/slog"
	"os"
	"slices"
	"strings"
)

// MeshAllowFromTargets reports whether mesh allowlist derivation and self
// filtering are active for the current mode.
func MeshAllowFromTargets() bool {
	return *Default.AllowFromTargets && *Default.Mode != "client"
}

// ResolveEchoSecret returns the echo HMAC secret from flag or env.
func ResolveEchoSecret() string {
	if *Default.EchoSecret != "" {
		return *Default.EchoSecret
	}
	return os.Getenv("LINK_PING_ECHO_SECRET")
}

// ResolveEchoSecretOld returns the rotation-previous echo HMAC secret
// from flag or env. Empty when no rotation is in progress.
func ResolveEchoSecretOld() string {
	if *Default.EchoSecretOld != "" {
		return *Default.EchoSecretOld
	}
	return os.Getenv("LINK_PING_ECHO_SECRET_OLD")
}

// WarnIgnoredFlags emits one-line slog.Warn diagnostics for flags that are
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
//   - with both -targets and -target set, BuildProberConfig's else-if means
//     -targets wins.
func WarnIgnoredFlags(mode string) {
	if ResolveEchoSecretOld() != "" && mode == "client" {
		slog.Warn("-echo-secret-old set but ignored: the old secret is only accepted by the echo server (server/both mode), not by the client")
	}
	// -listen's default (":4000") is non-empty, so compare against the
	// set-flag seam: a client run with the default must not warn.
	if *Default.Allow != "" && mode == "client" {
		slog.Warn("-allow set but ignored: the client allowlist only applies to the echo server (server/both mode)")
	}
	if *Default.AllowFromTargets && mode == "client" {
		slog.Warn("-allow-from-targets set but ignored: the derived allowlist and self-skip only apply to the echo server (server/both mode)")
	}
	if FlagWasSet("listen") && mode == "client" {
		slog.Warn("-listen set but ignored: the listen address only applies to the echo server (server/both mode)")
	}
	if *Default.Targets != "" && *Default.Target != "" && mode != "server" {
		slog.Warn("-targets and -target are both set: -targets wins, -target is ignored")
	}
	// -hmac-coverage shapes the tag the CLIENT writes; the echo server
	// accepts both coverages whenever -echo-secret is set, so the flag has
	// no effect in server-only mode.
	if FlagWasSet("hmac-coverage") && mode == "server" {
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
	if *Default.Source != "" {
		return *Default.Source
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

// ResolveSource returns the effective source label (the -source flag or the
// sanitized hostname) and validates it. One spelling for BuildProberConfig, the
// server-only run path and -svc=install: a source that fails
// ValidateTargetName must be refused by every caller, never persisted into a
// service command line that then exits 1 on each SCM start.
func ResolveSource() (string, error) {
	source := *Default.Source
	if source == "" {
		source = effectiveSource()
	}
	if err := prober.ValidateTargetName(source); err != nil {
		return "", fmt.Errorf("invalid -source: %w", err)
	}
	return source, nil
}

// warnShadowedAndWeakenedConfig surfaces two silent configurations that have
// caused real incidents:
//
//   - a flag silently shadowing a credential already present in the
//     environment. A unit file that keeps an old -echo-secret while the env
//     file is rotated leaves the retired secret as the primary forever,
//     because the env change has no effect and nothing says so.
//   - -hmac-coverage=header with -payload and a secret. The v0.7 escape hatch
//     authenticates the header only, so a payload tampered in flight (or
//     substituted under a captured header tag) still authenticates. It is
//     legitimate while a v0.7 reflector is still deployed; it must not be left
//     on afterwards by accident.
func warnShadowedAndWeakenedConfig(sf StartupFlags) {
	type shadow struct {
		flagName string
		flagVal  string
		envName  string
	}
	for _, sh := range []shadow{
		{"echo-secret", *Default.EchoSecret, "LINK_PING_ECHO_SECRET"},
		{"echo-secret-old", *Default.EchoSecretOld, "LINK_PING_ECHO_SECRET_OLD"},
		{"metrics-user", *Default.MetricsBasicAuthUser, "LINK_PING_METRICS_USER"},
		{"metrics-pass", *Default.MetricsBasicAuthPass, "LINK_PING_METRICS_PASS"},
	} {
		env := os.Getenv(sh.envName)
		if sh.flagVal == "" || env == "" || sh.flagVal == env {
			continue
		}
		slog.Warn("flag shadows the environment value: the environment one is ignored",
			"flag", "-"+sh.flagName, "env", sh.envName,
			"fix", "set only one of them, or make them identical")
	}

	if *Default.HMACCoverage == "header" && *Default.Payload > 0 && sf.EchoSecret != "" {
		slog.Warn("-hmac-coverage=header with -payload authenticates only the 24-byte header: a payload tampered in flight or substituted under a captured header tag still verifies; use full-frame unless the reflector is still v0.7")
	}
}

// BuildProberConfig resolves CLI flags into a prober.Config. It handles single
// (-target) and multi-target (-targets) modes. Failures are returned as
// errors so the caller can abort before any server starts.
func BuildProberConfig() (prober.Config, error) {
	var targets []prober.Target
	if *Default.Targets != "" {
		var err error
		targets, err = prober.LoadTargets(*Default.Targets)
		if err != nil {
			return prober.Config{}, fmt.Errorf("load targets: %w", err)
		}
	} else if *Default.Target != "" {
		if err := prober.ValidateTarget(*Default.Target); err != nil {
			return prober.Config{}, fmt.Errorf("invalid target: %w", err)
		}
		targets = []prober.Target{{Name: "default", Address: *Default.Target}}
	}
	source, err := ResolveSource()
	if err != nil {
		return prober.Config{}, err
	}
	// Mesh mode (-allow-from-targets) deploys ONE targets file on every
	// site, listing all of them including the local one. Drop the self entry
	// so the shared file probes only remote peers, and record the choice in
	// the config so the reload path applies the same filter — a reload that
	// re-added self would probe and export the local site.
	skipSelf := MeshAllowFromTargets()
	if skipSelf {
		targets = prober.FilterSelfTargets(targets, source)
	}
	cfg := prober.Config{
		Source:            source,
		Targets:           targets,
		SkipSelf:          skipSelf,
		Adaptive:          *Default.Adaptive,
		BaseInterval:      *Default.BaseInterval,
		BaseTimeout:       *Default.BaseTimeout,
		EchoSecret:        ResolveEchoSecret(),
		ReconnectInterval: *Default.ReconnectInterval,
		DSCP:              *Default.DSCP,
		Payload:           *Default.Payload,
		MTUSweep:          *Default.MTUSweep,
		TargetsPath:       *Default.Targets,
		ReloadInterval:    *Default.TargetsReload,
	}
	coverage, err := prober.ParseHMACCoverage(*Default.HMACCoverage)
	if err != nil {
		return prober.Config{}, err
	}
	cfg.HmacCoverage = coverage
	// Validate the whole config here so -svc=install and run() cannot accept
	// different configurations: both reach RunClient through this builder.
	// A self-only mesh file is diagnosed by ResolveAllowlist with a more
	// specific message ("no peers to derive an allowlist from"), so leave
	// the empty target set to it rather than preempting with "no targets".
	if !(skipSelf && len(targets) == 0) {
		if err := cfg.Validate(); err != nil {
			return prober.Config{}, err
		}
	}
	return cfg, nil
}

// ResolveMetricsAuth combines the CLI flags with the LINK_PING_METRICS_USER /
// LINK_PING_METRICS_PASS environment variables (flags win). Username and
// password must be configured as a pair: user-only would otherwise enable
// auth with an empty password.
func ResolveMetricsAuth() (string, string, error) {
	userFlag, passFlag := *Default.MetricsBasicAuthUser, *Default.MetricsBasicAuthPass
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

// StartupFlags is the resolved form of the flags that must be validated before
// anything is bound (run) or registered (install).
type StartupFlags struct {
	EchoSecret, EchoSecretOld string
	MetricsUser, MetricsPass  string
	MetricsCert, MetricsKey   string
}

// CheckStartupFlags validates mode, auth, and TLS flags before binding ports
// or registering an SCM service entry.
func CheckStartupFlags() (StartupFlags, error) {
	// A bad -mode should never open ports or start servers.
	switch mode := *Default.Mode; mode {
	case "server", "client", "both":
	default:
		return StartupFlags{}, fmt.Errorf("unknown mode: %s", mode)
	}

	// Rotation guard. ServePacketConn consults echoSecretOld only inside
	// its `if echoSecret != ""` branch (internal/prober/server.go), so an
	// old secret on its own authenticates NOTHING: with the primary secret
	// empty the agent runs unauthenticated while an operator mid-rotation
	// believes the rotation protection is active. Fail fast instead.
	sf := StartupFlags{EchoSecret: ResolveEchoSecret(), EchoSecretOld: ResolveEchoSecretOld()}
	if sf.EchoSecret == "" && sf.EchoSecretOld != "" {
		return StartupFlags{}, errors.New("-echo-secret-old is set without -echo-secret: the old secret alone provides no authentication (it is only accepted alongside a primary secret), so the agent would run unauthenticated; set -echo-secret or clear -echo-secret-old")
	}
	// Runs here (not in run()) so the ignored-flag warnings also reach an
	// operator at install time, when the persisted flags are still editable.
	WarnIgnoredFlags(*Default.Mode)
	warnShadowedAndWeakenedConfig(sf)

	user, pass, err := ResolveMetricsAuth()
	if err != nil {
		return StartupFlags{}, err
	}
	sf.MetricsUser, sf.MetricsPass = user, pass
	sf.MetricsCert, sf.MetricsKey = *Default.MetricsTLSCert, *Default.MetricsTLSKey
	if (sf.MetricsCert == "") != (sf.MetricsKey == "") {
		return StartupFlags{}, errors.New("-metrics-tls-cert and -metrics-tls-key must be set together")
	}
	if sf.MetricsCert != "" {
		// Validation only: the pair is loaded again by the listener, which
		// seeds its reload cache with it. Same provenance rule as the
		// listener: a symlink, a non-regular object, a foreign owner or a
		// group/world-readable key is refused before anything binds.
		if _, err := httpserver.LoadPair(sf.MetricsCert, sf.MetricsKey); err != nil {
			return StartupFlags{}, fmt.Errorf("metrics TLS: %w", err)
		}
	}
	if user != "" && sf.MetricsCert == "" && !*Default.MetricsAllowInsecure {
		return StartupFlags{}, errors.New("metrics basic auth requires TLS (-metrics-tls-cert/-key) or -metrics-allow-insecure to allow plaintext")
	}
	return sf, nil
}

// ResolveAllowlist resolves the echo responder's fail-closed client allowlist:
// -allow plus, in mesh mode, the peer list derived from the targets file. Shared
// by run() and -svc=install so the two cannot accept different configurations.
func ResolveAllowlist(mode string, cfg prober.Config) (*prober.Allowlist, error) {
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
	// self target was already dropped by BuildProberConfig. -allow still contributes,
	// so a mesh can also allow extra CIDRs explicitly.
	allowSpec := *Default.Allow
	if MeshAllowFromTargets() {
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
