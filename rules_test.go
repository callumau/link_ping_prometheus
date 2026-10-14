package main

import (
	"encoding/json"
	"flag"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"link_ping_prometheus/internal/prober"
)

// TestREADME_FlagsTableAndBucketsMatchCode ties the user-facing documentation
// to the code. Both have drifted before: -echo-secret was registered but
// missing from the flags table, and the bucket list lost its 2.5s/3s edges.
// A hand-maintained copy in a test would drift too, so this reads README.md
// itself. The comparison is one-directional (registered ⊆ documented): the
// README may legitimately show example rows the binary does not register.
func TestREADME_FlagsTableAndBucketsMatchCode(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	doc := string(data)

	rowRe := regexp.MustCompile("(?m)^\\| `(-[a-z0-9-]+)` \\|")
	documented := make(map[string]bool)
	for _, m := range rowRe.FindAllStringSubmatch(doc, -1) {
		documented[m[1]] = true
	}
	if len(documented) < 20 {
		t.Fatalf("parsed only %d flag rows from README.md — the table format changed, so this test would pass vacuously", len(documented))
	}
	flag.VisitAll(func(f *flag.Flag) {
		// go test registers its own -test.* flags in the same FlagSet: not
		// ours to document.
		if strings.HasPrefix(f.Name, "test.") {
			return
		}
		if !documented["-"+f.Name] {
			t.Errorf("flag -%s is registered in main.go but has no row in the README flags table", f.Name)
		}
	})

	bucketRe := regexp.MustCompile("explicit buckets `\\{([^}]+)\\}`")
	m := bucketRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("README no longer documents the RTT bucket edges as 'explicit buckets `{...}`'")
	}
	var want []float64
	for _, part := range strings.Split(m[1], ",") {
		v, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil {
			t.Fatalf("unparsable bucket edge %q in README: %v", part, err)
		}
		want = append(want, v)
	}
	if !slices.Equal(want, prober.RTTBuckets) {
		t.Errorf("README bucket list %v != prober.RTTBuckets %v — update both in the same commit", want, prober.RTTBuckets)
	}
}

// TestStatusEndpointIsGatedLikeMetrics: /status exposes live link state and
// peer addresses, so it must carry the same Basic auth as /metrics; /healthz
// and /readyz stay open for orchestrators. Pins the wiring in
// startMetricsServer, not just the MetricsAuth handler in isolation.

// TestRulesAndDashboardReferenceOnlyDefinedMetrics pins a coupling that has
// drifted before: a renamed metric silently turns a shipped alert or dashboard
// panel into "no data". Every link_* identifier in rules/link-monitor.yml and
// grafana-dashboard.json must be a metric defined in internal/prober/metrics.go
// (or one of the histogram suffixes the client library appends). promtool in CI
// would validate PromQL syntax, but not this, and the repo's suite needs nothing
// beyond go test.
// pi-lens-ignore: go-test-functions
func TestRulesAndDashboardReferenceOnlyDefinedMetrics(t *testing.T) {
	src, err := os.ReadFile("internal/prober/metrics.go")
	if err != nil {
		t.Fatal(err)
	}
	defined := make(map[string]bool)
	for _, m := range regexp.MustCompile(`Name:\s*"([a-z][a-z0-9_]*)"`).FindAllStringSubmatch(string(src), -1) {
		defined[m[1]] = true
	}
	if len(defined) < 15 {
		t.Fatalf("only %d metric names parsed from metrics.go — the extraction broke, so this test would pass vacuously", len(defined))
	}
	// Histogram series are exported with suffixes the code never spells out.
	isDefined := func(name string) bool {
		if defined[name] {
			return true
		}
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			if strings.HasSuffix(name, suffix) && defined[strings.TrimSuffix(name, suffix)] {
				return true
			}
		}
		return false
	}
	// Prose, not series: the binary/project name appears in comments and titles.
	notMetrics := map[string]bool{"link_ping": true, "link_ping_prometheus": true}

	for _, path := range []string{"rules/link-monitor.yml", "grafana-dashboard.json"} {
		// Fixed literals, not user input.
		// pi-lens-ignore: go-path-traversal
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		refs := regexp.MustCompile(`\blink_[a-z0-9_]+`).FindAllString(string(body), -1)
		if len(refs) < 15 {
			t.Fatalf("%s references only %d link_* names — the extraction broke", path, len(refs))
		}
		seen := make(map[string]bool, len(refs))
		for _, ref := range refs {
			if seen[ref] || notMetrics[ref] {
				continue
			}
			seen[ref] = true
			if !isDefined(ref) {
				t.Errorf("%s references %q, which internal/prober/metrics.go does not define (renamed metric? the alert/panel would read 'no data')", path, ref)
			}
		}
	}
}

// TestDashboardAndRules_RateWindowsMatch pins the AGENTS.md convention that
// a ratio expression must use the SAME rate() window in numerator and
// denominator: mismatched windows read wrong across restarts and scrape
// gaps (after a restart one side's rate is 0 while the other still sees
// pre-restart traffic, silently corrupting loss %/mean RTT). Every
// expression in grafana-dashboard.json (all "expr" values) and
// rules/link-monitor.yml (all rule exprs) that contains a division and a
// rate()/irate() must use one single rate window. Subquery brackets
// ([24h:5m]) are skipped — they are not rate windows.

// TestDashboardAndRules_RateWindowsMatch pins the AGENTS.md convention that
// a ratio expression must use the SAME rate() window in numerator and
// denominator: mismatched windows read wrong across restarts and scrape
// gaps (after a restart one side's rate is 0 while the other still sees
// pre-restart traffic, silently corrupting loss %/mean RTT). Every
// expression in grafana-dashboard.json (all "expr" values) and
// rules/link-monitor.yml (all rule exprs) that contains a division and a
// rate()/irate() must use one single rate window. Subquery brackets
// ([24h:5m]) are skipped — they are not rate windows.
func TestDashboardAndRules_RateWindowsMatch(t *testing.T) {
	windowRe := regexp.MustCompile(`\[(\$?[0-9]+(?:\.[0-9]+)?[smhd]|\$?__rate_interval)\]`)
	// [X:Y] is a subquery selector, not a rate window.
	subqueryRe := regexp.MustCompile(`\[[^]\[]*:[^]\[]*\]`)

	check := func(path, expr string) {
		t.Helper()
		if !strings.Contains(expr, "rate(") || !strings.Contains(expr, "/") {
			return
		}
		clean := subqueryRe.ReplaceAllString(expr, "")
		windows := windowRe.FindAllString(clean, -1)
		uniq := make(map[string]bool, len(windows))
		for _, w := range windows {
			// $__rate_interval and __rate_interval are the same window.
			uniq[strings.TrimPrefix(strings.TrimPrefix(w, "["), "$")] = true
		}
		if len(windows) == 0 {
			t.Errorf("%s: ratio expression has no extractable rate window (the extraction broke): %q", path, expr)
			return
		}
		if len(uniq) > 1 {
			t.Errorf("%s: ratio expression mixes rate() windows %v — numerator and denominator MUST match or the ratio reads wrong across restarts and scrape gaps: %q", path, windows, expr)
		}
	}

	// Dashboard: every query expression in the v2 schema (spec.elements).
	dashBody, err := os.ReadFile("grafana-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var dash any
	if err := json.Unmarshal(dashBody, &dash); err != nil {
		t.Fatal(err)
	}
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if expr, ok := v["expr"].(string); ok {
				check("grafana-dashboard.json", expr)
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(dash)

	// Rules file: every rule's expr, split on the rule markers so each
	// expression (and its numerator/denominator) is checked in isolation.
	rulesBody, err := os.ReadFile("rules/link-monitor.yml")
	if err != nil {
		t.Fatal(err)
	}
	exprRe := regexp.MustCompile(`(?m)^\s+(?:expr|recording)\s*:\s*(?:\|>?)?\s*\n((?:\s{10,}.*\n?)+)|^\s+expr:\s*(.+)$`)
	for _, m := range exprRe.FindAllStringSubmatch(string(rulesBody), -1) {
		expr := m[1] + m[2]
		check("rules/link-monitor.yml", strings.TrimSpace(expr))
	}
}

// TestProgramStopTimeoutReportsCleanStop pins the audit fix: a Stop whose
// drain exceeds svcStopDeadline must report a CLEAN stop (nil error).
// kardianos maps a Stop error to STOPPED with a service-specific exit
// code, which the SCM counts as a FAILURE — the OnFailure restart ladder
// would then bring the service back up in the middle of the maintenance
// window the operator just opened.
