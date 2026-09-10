package prober

import (
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
