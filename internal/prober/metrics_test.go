package prober_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"link_ping_prometheus/internal/prober"
)

// TestLinkUpHelpPinsMissThreshold keeps the user-facing Help text in sync
// with the tunable constant so changing one without the other fails CI.
func TestLinkUpHelpPinsMissThreshold(t *testing.T) {
	gauge, err := prober.LinkUp.GetMetricWithLabelValues("x", "y", "z")
	if err != nil {
		t.Fatalf("seeded LinkUp metric not found: %v", err)
	}
	help := gauge.Desc().String()
	want := fmt.Sprintf("%d consecutive probes time out (LinkUpMissThreshold)", prober.LinkUpMissThreshold)
	if !strings.Contains(help, want) {
		t.Errorf("LinkUp Help does not mention current LinkUpMissThreshold (%q):\n%s", want, help)
	}
}

// TestSeedMetrics verifies every metric series exists for a fresh target
// immediately after seeding — checked via the registry, since
// WithLabelValues would create the series as a side effect of reading.
func TestSeedMetrics(t *testing.T) {
	prober.InitMetrics()

	name := "seed_unique_target"
	prober.SeedMetrics(testSource, []prober.Target{{Name: name, Address: "192.0.2.1:4000"}})

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			for _, l := range m.Label {
				if l.GetName() == "target" && l.GetValue() == name {
					found[mf.GetName()] = true
				}
			}
		}
	}

	want := []string{
		"link_probes_sent_total",
		"link_probes_timed_out_total",
		"link_probes_send_errors_total",
		"link_probes_throttled_total",
		"link_probes_corrupted_total",
		"link_mtu_probes_sent_total",
		"link_mtu_probes_lost_total",
		"link_path_mtu_bytes",
		"link_probes_inflight",
		"link_up",
		"link_rto_seconds",
		"link_rtt_srtt_seconds",
		"link_rtt_seconds",
		"link_rtt_jitter_seconds",
	}
	for _, w := range want {
		if !found[w] {
			t.Errorf("metric %s has no series for freshly seeded target", w)
		}
	}
}
