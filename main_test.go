package main

import (
	"bytes"
	"context"
	dto "github.com/prometheus/client_model/go"
	"log/slog"
	"net/http"
	"testing"
)

// chanHandler forwards log records to a channel so the scavenger test can
// observe a tick without sleeping for a real interval.
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

// pi-lens-ignore: go-test-functions

// saveFlags restores all mutated global flags after the test.
func saveFlags(t *testing.T) {
	t.Helper()
	oldMode, oldListen, oldMetrics := *flMode, *flListen, *flMetrics
	oldTarget, oldTargets := *flTarget, *flTargets
	oldUser, oldPass := *flMetricsBasicAuthUser, *flMetricsBasicAuthPass
	oldCert, oldKey := *flMetricsTLSCert, *flMetricsTLSKey
	oldAllow, oldAllowFromTargets, oldSource := *flAllow, *flAllowFromTargets, *flSource
	oldAdaptive := *flAdaptive
	oldInterval, oldTimeout := *flBaseInterval, *flBaseTimeout
	oldReconnect, oldPayload, oldDSCP := *flReconnectInterval, *flPayload, *flDSCP
	oldTargetsReload, oldMTUSweep := *flTargetsReload, *flMTUSweep
	oldLogFile, oldJSONLogs := *flLogFile, *flJSONLogs
	oldLogMaxSize, oldLogMaxBackups, oldLogMaxAge := *flLogMaxSize, *flLogMaxBackups, *flLogMaxAge
	oldAllowInsecure := *flMetricsAllowInsecure
	oldEchoSecret, oldEchoSecretOld := *flEchoSecret, *flEchoSecretOld
	t.Cleanup(func() {
		*flMode, *flListen, *flMetrics = oldMode, oldListen, oldMetrics
		*flTarget, *flTargets = oldTarget, oldTargets
		*flMetricsBasicAuthUser, *flMetricsBasicAuthPass = oldUser, oldPass
		*flMetricsTLSCert, *flMetricsTLSKey = oldCert, oldKey
		*flAllow, *flSource = oldAllow, oldSource
		*flAllowFromTargets = oldAllowFromTargets
		*flAdaptive = oldAdaptive
		*flBaseInterval, *flBaseTimeout = oldInterval, oldTimeout
		*flReconnectInterval, *flPayload, *flDSCP = oldReconnect, oldPayload, oldDSCP
		*flTargetsReload, *flMTUSweep = oldTargetsReload, oldMTUSweep
		*flLogFile, *flJSONLogs = oldLogFile, oldJSONLogs
		*flLogMaxSize, *flLogMaxBackups, *flLogMaxAge = oldLogMaxSize, oldLogMaxBackups, oldLogMaxAge
		*flMetricsAllowInsecure = oldAllowInsecure
		*flEchoSecret, *flEchoSecretOld = oldEchoSecret, oldEchoSecretOld
	})
}

// pi-lens-ignore: go-test-functions

// captureWarns swaps the default slog logger for a buffered text handler so
// tests can assert startup warnings fired. Restores the previous default on
// cleanup (tests are sequential: no parallel test may rely on the default
// logger while the buffer is installed).
func captureWarns(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// blockingGatherer parks every Gather until release is closed, making the
// MaxRequestsInFlight cap deterministic: without the park, the cap could only
// be tested by racing real gathers against each other.
type blockingGatherer struct {
	entered chan struct{}
	release chan struct{}
}

func (g *blockingGatherer) Gather() ([]*dto.MetricFamily, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	return nil, nil
}

// blockingStatusHandler parks every request until release is closed, making
// the /status concurrency cap deterministic (the same pattern as
// blockingGatherer for /metrics). After release is closed, later requests
// complete immediately, so the test can verify slots are reusable afterward.
type blockingStatusHandler struct {
	entered chan struct{}
	release chan struct{}
}

func (h *blockingStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
}

// funcWriter adapts a function to io.Writer for sink tests.
type funcWriter func([]byte) (int, error)

func (f funcWriter) Write(p []byte) (int, error) { return f(p) }

// TestCountedWriterFailureStreak pins drainFailures semantics: failures
// accumulate between drains, a drain clears the streak, and a
// successful write resets it.
