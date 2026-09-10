package prober

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// benchSink absorbs a value derived from a benchmarked buffer so the
// compiler cannot discard the work under test as dead stores.
var benchSink uint64

// BenchmarkTargetMetricsResolution documents the "resolve metric handles
// once per target" design choice: client.go's targetMetrics struct grabs
// every CounterVec/GaugeVec handle when a target's loop starts and calls
// methods on those handles on the hot path, instead of calling
// WithLabelValues(...) per probe event.
//
// Both sub-benchmarks do identical work (increment one counter) through
// the two coding styles, so their ns/op ratio is the per-probe
// label-map lookup cost the design avoids. The CounterVec is constructed
// locally and never registered, so the benchmark cannot perturb the
// package's global metric vecs or the DefaultGatherer shared with every
// other test in this binary.
func BenchmarkTargetMetricsResolution(b *testing.B) {
	vec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bench_target_metric_resolution_total",
		Help: "benchmark-local counter; intentionally never registered",
	}, []string{"source", "target", "address"})
	const source, target, address = "bench", "bench-target", "127.0.0.1:9"

	b.Run("resolve_once", func(b *testing.B) {
		c := vec.WithLabelValues(source, target, address)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Inc()
		}
	})

	b.Run("per_event_lookup", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			vec.WithLabelValues(source, target, address).Inc()
		}
	})
}

// BenchmarkFillPayload measures the -payload hot path: one 1400-byte
// deterministic pattern fill per probe, before the datagram is written.
//
// It protects the deliberate choice of a pure in-place xorshift64* fill:
// regenerating the pattern must never allocate and must stay a single
// linear pass, because it runs once per sent probe on every target. A
// regression to a per-byte allocation or an external entropy source would
// surface here as ns/op and allocs/op, not as a correctness failure.
func BenchmarkFillPayload(b *testing.B) {
	buf := make([]byte, MaxPayloadBytes)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fillPayload(buf, uint64(i), uint64(i))
	}
	benchSink = uint64(buf[0]) ^ uint64(buf[len(buf)-1])
}

// BenchmarkAllowlistContains measures the first check every datagram pays,
// from an untrusted source and before any crypto: the allowlist decision. It
// documents the netip.Addr keying — taking the source as a value plus Unmap
// costs ~9ns with zero allocations, where the earlier
// IP.String()-then-ParseAddr form measured ~89ns and one 16-byte allocation
// per packet (same containment test). At the MaxPktsGlobal cap that is ~10k
// allocations/sec removed from the pre-auth path, i.e. less work an attacker
// can force on a latency-measuring box. A regression back to string keying
// shows up here as allocs/op > 0.
func BenchmarkAllowlistContains(b *testing.B) {
	al, err := ParseAllowlist("203.0.113.5,10.0.0.0/8,2001:db8::/32")
	if err != nil {
		b.Fatal(err)
	}
	exact := netip.MustParseAddr("203.0.113.5")
	prefix := netip.MustParseAddr("10.4.5.6")
	v6 := netip.MustParseAddr("2001:db8::1")
	src := netip.MustParseAddr("203.0.113.7")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok := al.Contains(exact) && al.Contains(prefix) && al.Contains(v6) && !al.Contains(src)
		if !ok {
			b.Fatal("allowlist lookup regressed: a configured entry stopped matching")
		}
	}
}
