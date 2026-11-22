package service

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"link_ping_prometheus/internal/config"
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

// saveFlags restores all mutated global flags after the test.
func saveFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(config.SnapshotFlagsForTest())
}

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
