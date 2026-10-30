package prober_test

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"link_ping_prometheus/internal/prober"
)

// testSource is the topology label applied in test metric queries.
const testSource = "test"

// getCounterValue reads a counter series, prepending testSource to the
// given labels (variadic: 2 labels for client metrics, 1 for the server
// metric).
func getCounterValue(vec *prometheus.CounterVec, labels ...string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(append([]string{testSource}, labels...)...).Write(&m); err != nil {
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

func verifyHistogramCount(t *testing.T, vec *prometheus.HistogramVec, targetName, address string) {
	t.Helper()
	val := getHistogramCount(vec, targetName, address)
	if val <= 0 {
		t.Errorf("expected histogram sample count > 0 for target %s (addr %s), got %v", targetName, address, val)
	}
}

// buildFrame assembles one wire probe frame: magic, little-endian sequence,
// little-endian unix-ns timestamp, an optional 8-byte tag at offset 24, and
// payloadLen zero-filled payload bytes. headerSize is prober.PayloadSize or
// prober.PayloadSizeWithHMAC; a payload-bearing header frame passes the
// former and puts the tag in the first 8 payload bytes. Callers supply the tag
// and fill the payload themselves: tag computation and payload patterns stay
// independent of the prober package on purpose.
func buildFrame(headerSize int, seq, ts uint64, payloadLen int, tag []byte) []byte {
	f := make([]byte, headerSize+payloadLen)
	copy(f[0:8], prober.MagicBytes)
	binary.LittleEndian.PutUint64(f[8:16], seq)
	binary.LittleEndian.PutUint64(f[16:24], ts)
	if tag != nil {
		copy(f[24:32], tag)
	}
	return f
}

// pollUntil evaluates cond every sleep until it reports true or timeout
// elapses, returning the final result. It is the shared spelling of the
// time-first wait loops in this package; condition side effects (recording the
// last observed value) are preserved because cond is not called after the
// deadline has passed.
func pollUntil(t *testing.T, timeout, sleep time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(sleep)
	}
	return false
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
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(d)
}

// runClientSettle is runClientFor followed by a cancel and a settle
// period so in-flight probe bookkeeping finishes before counters are
// read.
func runClientSettle(ctx context.Context, cancel context.CancelFunc, cfg prober.Config, run time.Duration) {
	go prober.RunClient(ctx, cfg)
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(run)
	cancel()
	// pi-lens-ignore: go-time-sleep-test
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

// runClientAsync launches RunClient in a goroutine and registers a
// cleanup that cancels ctx and joins the probe loop, failing the test
// if the client does not stop within 2s. Returns the done channel for
// tests that need to observe stop timing.
func runClientAsync(t *testing.T, ctx context.Context, cancel context.CancelFunc, cfg prober.Config) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = prober.RunClient(ctx, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("RunClient did not stop after cancel")
		}
	})
	return done
}

// dialFrom opens a UDP connection to addr bound to the given source IP,
// for tests that exercise per-source server behavior (rate limits,
// allowlist prefixes). Not every host can bind a loopback alias
// (127.0.0.2, 127.0.0.3, ...) — Windows local runs notably cannot — so a
// bind failure SKIPS the calling test instead of failing it: whether a
// loopback alias is addressable is an environment property, not the
// property under test.
func dialFrom(t *testing.T, addr string, ip net.IP) net.Conn {
	t.Helper()
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: ip, Port: 0}, dst)
	if err != nil {
		t.Skipf("source address %s is not bindable on this host (loopback aliases are Linux-only): %v", ip, err)
	}
	return conn
}

// echoOnce sends one LNKPING probe on conn and reports whether a
// full-size echo came back within 300ms.
func echoOnce(t *testing.T, conn net.Conn) bool {
	t.Helper()
	probe := buildFrame(prober.PayloadSize, 0, 0, 0, nil)
	conn.Write(probe)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, _ := conn.Read(make([]byte, prober.PayloadSize))
	return n == prober.PayloadSize
}

// logCapture is a slog.Handler recording every record (message + attrs) that
// passes through it, so tests can assert a specific warning was emitted — and
// how often. slog's default logger is process-global, so a capture is only
// valid while the test under it owns the default: install with
// withLogCapture (or SetDefault + defer restore) and never combine with
// tests that rely on another handler concurrently (the suite runs
// sequentially within a package).
type logCapture struct {
	mu      sync.Mutex
	records []string
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
		return true
	})
	c.records = append(c.records, b.String())
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

// count returns how many captured records contain substr.
func (c *logCapture) count(substr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.records {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

// find returns the first captured record containing substr, or "".
func (c *logCapture) find(substr string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.records {
		if strings.Contains(r, substr) {
			return r
		}
	}
	return ""
}

// withLogCapture installs c as the default slog handler for the duration of
// fn and restores the previous default afterwards.
func withLogCapture(c *logCapture, fn func()) {
	old := slog.Default()
	slog.SetDefault(slog.New(c))
	defer slog.SetDefault(old)
	fn()
}
