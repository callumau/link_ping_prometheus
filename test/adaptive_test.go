package prober_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// The AdaptiveStats unit tests (SRTT/RTTVAR/RTO math, backoff clamping,
// dynamic floor) live in internal/prober/adaptive_test.go, in-package,
// where they read the unexported fields directly.

func TestAdaptive_RespondsToJitter(t *testing.T) {
	prober.InitMetrics()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	var delay atomic.Int64
	delay.Store(int64(10 * time.Millisecond))

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, prober.PayloadSize)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			// pi-lens-ignore: go-time-sleep-test
			time.Sleep(time.Duration(delay.Load()))
			// pi-lens-ignore: go-ignored-call-result
			conn.Write(buf)
		}
	}()

	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(true, 50*time.Millisecond, 500*time.Millisecond, prober.Target{Name: "adaptive_jitter", Address: addr})
	go prober.RunClient(ctx, cfg)

	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(1 * time.Second)
	rtoLow := getGaugeValue(prober.RTOEstimate, "adaptive_jitter", addr)

	delay.Store(int64(150 * time.Millisecond))
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(2 * time.Second)
	rtoHigh := getGaugeValue(prober.RTOEstimate, "adaptive_jitter", addr)

	t.Logf("RTO Low: %v, RTO High: %v", rtoLow, rtoHigh)

	if rtoHigh <= rtoLow {
		t.Errorf("RTO should allow adaptation: high latency %v should > low latency %v", rtoHigh, rtoLow)
	}
	if rtoHigh < 0.15 {
		t.Errorf("RTO High %v is too low for 150ms latency", rtoHigh)
	}
}
