package prober

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// stubConn is an embeddable net.Conn with optional per-method hooks and
// no-op/EOF defaults so white-box socket tests only override the methods they
// exercise.
type stubConn struct {
	readFn             func([]byte) (int, error)
	writeFn            func([]byte) (int, error)
	closeFn            func() error
	setReadDeadlineFn  func(time.Time) error
	setWriteDeadlineFn func(time.Time) error
	localAddrFn        func() net.Addr
	remoteAddrFn       func() net.Addr
}

func (s stubConn) Read(b []byte) (int, error) {
	if s.readFn != nil {
		return s.readFn(b)
	}
	return 0, io.EOF
}

func (s stubConn) Write(b []byte) (int, error) {
	if s.writeFn != nil {
		return s.writeFn(b)
	}
	return len(b), nil
}

func (s stubConn) Close() error {
	if s.closeFn != nil {
		return s.closeFn()
	}
	return nil
}

func (s stubConn) LocalAddr() net.Addr {
	if s.localAddrFn != nil {
		return s.localAddrFn()
	}
	return nil
}

func (s stubConn) RemoteAddr() net.Addr {
	if s.remoteAddrFn != nil {
		return s.remoteAddrFn()
	}
	return nil
}

func (s stubConn) SetDeadline(time.Time) error { return nil }

func (s stubConn) SetReadDeadline(t time.Time) error {
	if s.setReadDeadlineFn != nil {
		return s.setReadDeadlineFn(t)
	}
	return nil
}

func (s stubConn) SetWriteDeadline(t time.Time) error {
	if s.setWriteDeadlineFn != nil {
		return s.setWriteDeadlineFn(t)
	}
	return nil
}

// wbCounter reads a counter series for the given client labels.
func wbCounter(vec *prometheus.CounterVec, source, name, addr string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(source, name, addr).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// wbGauge reads a gauge series for the given client labels.
func wbGauge(vec *prometheus.GaugeVec, source, name, addr string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(source, name, addr).Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// wbHistCount reads an RTT histogram sample count.
func wbHistCount(source, name, addr string) float64 {
	obs, err := RTTSeconds.GetMetricWithLabelValues(source, name, addr)
	if err != nil {
		return 0
	}
	var d dto.Metric
	if err := obs.(prometheus.Metric).Write(&d); err != nil {
		return 0
	}
	return float64(d.GetHistogram().GetSampleCount())
}

// wbCounterLabels reads a counter series by its full label set. Unlike
// wbCounter it handles vecs whose label cardinality differs from the
// client {source,target,address} shape (e.g. ProberInternalErrors, which
// adds a reason label).
func wbCounterLabels(vec *prometheus.CounterVec, labels ...string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(labels...).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// wbRealEchoServer starts a production ServePacketConn echo responder on
// an ephemeral loopback port with a fail-closed allowlist, closing it on
// ctx cancellation. Unlike wbEchoServer it validates frames exactly like
// a deployed server (allowlist, size, magic), so link-up tests observe a
// genuine end-to-end echo rather than an unconditional reflector.
func wbRealEchoServer(t *testing.T, ctx context.Context, secret string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := ParseAllowlist("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go func() {
		ServePacketConn(ctx, pc, "test", allowed, secret)
	}()
	return pc.LocalAddr().String()
}

// buildFrame assembles one wire probe frame: magic, little-endian sequence,
// little-endian unix-ns timestamp, an optional 8-byte tag at offset 24, and
// payloadLen zero-filled payload bytes. headerSize is PayloadSize or
// PayloadSizeWithHMAC; callers pass nil when the frame carries no tag. Tag
// computation and payload filling stay with the caller so each test keeps its
// independent spec instead of validating the contract against itself.
func buildFrame(headerSize int, seq, ts uint64, payloadLen int, tag []byte) []byte {
	f := make([]byte, headerSize+payloadLen)
	copy(f[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(f[8:16], seq)
	binary.LittleEndian.PutUint64(f[16:24], ts)
	if tag != nil {
		copy(f[24:32], tag)
	}
	return f
}
