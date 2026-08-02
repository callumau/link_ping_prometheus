package prober_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"tcp_ping_prometheus/internal/prober"
)

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
	if err := vec.WithLabelValues(targetName, address).Write(&m); err != nil {
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
	if err := vec.WithLabelValues(label1).Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func getGaugeValue(vec *prometheus.GaugeVec, targetName, address string) float64 {
	var m dto.Metric
	if err := vec.WithLabelValues(targetName, address).Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

func getHistogramMean(vec *prometheus.HistogramVec, targetName, address string) float64 {
	obs, err := vec.GetMetricWithLabelValues(targetName, address)
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

func verifyCounter(t *testing.T, vec *prometheus.CounterVec, targetName, address string) {
	t.Helper()
	val := getCounterValue(vec, targetName, address)
	if val <= 0 {
		t.Errorf("expected metric value > 0 for target %s (addr %s), got %v", targetName, address, val)
	}
}

func startEchoServer(ctx context.Context, t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, prober.PayloadSize)
				for {
					c.SetReadDeadline(time.Now().Add(10 * time.Second))
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func makeTargets(count int) []prober.Target {
	targets := make([]prober.Target, count)
	for i := range count {
		targets[i] = prober.Target{
			Name:    fmt.Sprintf("t%d", i),
			Address: fmt.Sprintf("127.0.0.1:%d", 4000+i),
		}
	}
	return targets
}

func cfgWith(adaptive bool, interval, timeout time.Duration, targets ...prober.Target) prober.Config {
	return prober.Config{
		Targets:      targets,
		Adaptive:     adaptive,
		BaseInterval: interval,
		BaseTimeout:  timeout,
	}
}
