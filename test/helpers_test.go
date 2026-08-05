package prober_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"link_ping_prometheus/internal/prober"
)

// testSource is the topology label applied in test metric queries.
const testSource = "test"

type testGlobals struct {
	adaptive bool
	interval time.Duration
	timeout  time.Duration
}

type atomicLatency struct {
	v atomic.Int64
}

func (a *atomicLatency) set(d time.Duration) {
	a.v.Store(int64(d))
}
func (a *atomicLatency) get() time.Duration {
	return time.Duration(a.v.Load())
}

func getCounterValue(vec *prometheus.CounterVec, targetName, address string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(testSource, targetName, address).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func getPlainCounterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func getCounterValue1(vec *prometheus.CounterVec, label1 string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(testSource, label1).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func getGaugeValue(vec *prometheus.GaugeVec, targetName, address string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(testSource, targetName, address).Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

func getHistogramMean(vec *prometheus.HistogramVec, targetName, address string) float64 {
	obs, err := vec.GetMetricWithLabelValues(testSource, targetName, address)
	if err != nil {
		return 0
	}
	m, ok := obs.(prometheus.Metric)
	if !ok {
		return 0
	}
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return 0
	}
	h := d.GetHistogram()
	if h.GetSampleCount() == 0 {
		return 0
	}
	return h.GetSampleSum() / float64(h.GetSampleCount())
}

// getHistogramCount returns the number of observed RTT samples for a
// target — the monitoring-visible count of received responses.
func getHistogramCount(vec *prometheus.HistogramVec, targetName, address string) float64 {
	obs, err := vec.GetMetricWithLabelValues(testSource, targetName, address)
	if err != nil {
		return 0
	}
	m, ok := obs.(prometheus.Metric)
	if !ok {
		return 0
	}
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return 0
	}
	return float64(d.GetHistogram().GetSampleCount())
}

func verifyCounter(t *testing.T, vec *prometheus.CounterVec, targetName, address string) {
	t.Helper()
	val := getCounterValue(vec, targetName, address)
	if val <= 0 {
		t.Errorf("expected metric value > 0 for target %s (addr %s), got %v", targetName, address, val)
	}
}

func verifyHistogramCount(t *testing.T, vec *prometheus.HistogramVec, targetName, address string) {
	t.Helper()
	val := getHistogramCount(vec, targetName, address)
	if val <= 0 {
		t.Errorf("expected histogram sample count > 0 for target %s (addr %s), got %v", targetName, address, val)
	}
}

// startEchoServer starts a UDP echo responder on an ephemeral port that
// echoes every validated probe, returning its address. It is used as the
// healthy remote endpoint in client tests.
func startEchoServer(ctx context.Context, t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != prober.PayloadSize || string(buf[0:8]) != prober.MagicBytes {
				continue
			}
			pc.WriteTo(buf[:n], raddr)
		}
	}()
	return pc.LocalAddr().String()
}

func cfgWith(adaptive bool, interval, timeout time.Duration, targets ...prober.Target) prober.Config {
	return prober.Config{
		Source:       testSource,
		Targets:      targets,
		Adaptive:     adaptive,
		BaseInterval: interval,
		BaseTimeout:  timeout,
	}
}
