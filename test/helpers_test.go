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

// histogramMetric returns the dto.Histogram for a target's series, or
// nil when the series has no metric data yet. Shared by the mean and
// count getters so they never duplicate the read/write boilerplate.
func histogramMetric(vec *prometheus.HistogramVec, targetName, address string) *dto.Histogram {
	obs, err := vec.GetMetricWithLabelValues(testSource, targetName, address)
	if err != nil {
		return nil
	}
	m, ok := obs.(prometheus.Metric)
	if !ok {
		return nil
	}
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return nil
	}
	return d.GetHistogram()
}

func getHistogramMean(vec *prometheus.HistogramVec, targetName, address string) float64 {
	h := histogramMetric(vec, targetName, address)
	if h == nil || h.GetSampleCount() == 0 {
		return 0
	}
	return h.GetSampleSum() / float64(h.GetSampleCount())
}

// getHistogramCount returns the number of observed RTT samples for a
// target — the monitoring-visible count of received responses.
func getHistogramCount(vec *prometheus.HistogramVec, targetName, address string) float64 {
	h := histogramMetric(vec, targetName, address)
	if h == nil {
		return 0
	}
	return float64(h.GetSampleCount())
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

// listenUDP opens a loopback UDP socket that is closed when ctx is
// cancelled. Shared by every echo-responder helper so tests never
// duplicate socket-lifecycle boilerplate.
func listenUDP(t *testing.T, ctx context.Context) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	return pc
}

// startEchoServer starts a UDP echo responder on an ephemeral port that
// echoes every validated probe, returning its address. It is used as the
// healthy remote endpoint in client tests.
func startEchoServer(ctx context.Context, t *testing.T) string {
	t.Helper()
	return udpEcho(t, ctx, echoAll)
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

// runClientFor launches RunClient for the target config and lets it
// probe for d. Tests then read end-state counters.
func runClientFor(ctx context.Context, cfg prober.Config, d time.Duration) {
	go prober.RunClient(ctx, cfg)
	time.Sleep(d)
}

// runClientSettle is runClientFor followed by a cancel and a settle
// period so in-flight probe bookkeeping finishes before counters are
// read.
func runClientSettle(ctx context.Context, cancel context.CancelFunc, cfg prober.Config, run time.Duration) {
	go prober.RunClient(ctx, cfg)
	time.Sleep(run)
	cancel()
	time.Sleep(100 * time.Millisecond)
}

// recvTimeoutCounters returns (RTT histogram sample count, timeout
// counter) for a target series — the pair of counters robustness tests
// compare before and after a run.
func recvTimeoutCounters(targetName, addr string) (float64, float64) {
	return getHistogramCount(prober.RTTSeconds, targetName, addr),
		getCounterValue(prober.ProbesTimedOut, targetName, addr)
}

// recvSentCounters returns (RTT histogram sample count, sent counter)
// for a target series.
func recvSentCounters(targetName, addr string) (float64, float64) {
	return getHistogramCount(prober.RTTSeconds, targetName, addr),
		getCounterValue(prober.ProbesSent, targetName, addr)
}

// namedCfg builds a single-target, non-adaptive config and returns it
// with its label name — the shared preamble of every probe test.
func namedCfg(name, addr string, interval, timeout time.Duration) (string, prober.Config) {
	return name, cfgWith(false, interval, timeout, prober.Target{Name: name, Address: addr})
}

// validatedEcho is udpEcho with the standard probe-validation gate
// already applied, so handlers only contain their own behaviour.
func validatedEcho(t *testing.T, ctx context.Context, body func(buf []byte, w func([]byte))) string {
	return udpEcho(t, ctx, func(buf []byte, w func([]byte)) {
		if len(buf) != prober.PayloadSize || string(buf[0:8]) != prober.MagicBytes {
			return
		}
		body(buf, w)
	})
}
