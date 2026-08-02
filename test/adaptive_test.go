package prober_test

import (
	"context"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"tcp_ping_prometheus/internal/prober"
)

func TestAdaptiveStats_Logic(t *testing.T) {
	stats := prober.NewAdaptiveStats(1 * time.Second)

	if stats.SRTT() != 0 {
		t.Errorf("Expected initial SRTT 0, got %f", stats.SRTT())
	}

	rtt := 0.100
	stats.Update(rtt)
	if math.Abs(stats.SRTT()-0.1) > 0.0001 {
		t.Errorf("After 1st update: expected SRTT 0.1, got %f", stats.SRTT())
	}
	if math.Abs(stats.RTTVar()-0.05) > 0.0001 {
		t.Errorf("After 1st update: expected RTTVAR 0.05, got %f", stats.RTTVar())
	}
	if math.Abs(stats.RTO()-0.3) > 0.0001 {
		t.Errorf("After 1st update: expected RTO 0.3, got %f", stats.RTO())
	}

	stats.Update(0.100)
	if math.Abs(stats.RTO()-0.25) > 0.0001 {
		t.Errorf("After 2nd update: expected RTO 0.25, got %f", stats.RTO())
	}

	stats.Update(0.200)
	if stats.RTO() <= 0.25 {
		t.Errorf("Expected RTO to increase after spike, got %f", stats.RTO())
	}
}

func TestAdaptiveStats_BackoffClampedAndConsecutive(t *testing.T) {
	stats := prober.NewAdaptiveStats(1 * time.Second)

	// First timeout in a series must NOT double the RTO (RFC 6298:
	// doubling applies to retransmissions, not the initial timeout).
	stats.Backoff()
	if stats.RTO() != 1.0 {
		t.Errorf("first backoff must not double RTO, got %f", stats.RTO())
	}

	// Subsequent consecutive timeouts double, but never beyond the clamp.
	stats.Backoff()
	if math.Abs(stats.RTO()-2.0) > 0.0001 {
		t.Errorf("expected RTO 2.0 after second consecutive timeout, got %f", stats.RTO())
	}
	stats.Backoff()
	if math.Abs(stats.RTO()-4.0) > 0.0001 && stats.RTO() != prober.DefaultMaxRTO.Seconds() {
		t.Errorf("expected RTO 4.0 clamped to DefaultMaxRTO after third consecutive timeout, got %f", stats.RTO())
	}

	// Repeated backoffs must saturate at DefaultMaxRTO, not overflow.
	max := prober.DefaultMaxRTO.Seconds()
	for i := 0; i < 200; i++ {
		stats.Backoff()
	}
	if r := stats.CurrentRTO(); r != prober.DefaultMaxRTO {
		t.Errorf("expected RTO clamped to DefaultMaxRTO %v, got %v", prober.DefaultMaxRTO, r)
	}
	if stats.RTO() != max {
		t.Errorf("expected internal RTO clamped to %f, got %f", max, stats.RTO())
	}

	// A successful measurement resets the consecutive-timeout counter.
	stats.Update(0.1)
	stats.Backoff()
	if stats.RTO() != stats.SRTT()+4*stats.RTTVar() {
		t.Errorf("after success, next backoff must not double: got %f", stats.RTO())
	}
}

func TestAdaptiveStats_RTOFloorAndGranularity(t *testing.T) {
	// Hard floor: even a tiny base timeout must clamp to 200ms.
	stats := prober.NewAdaptiveStats(10 * time.Millisecond)
	if r := stats.CurrentRTO(); r != prober.DefaultMinRTO {
		t.Errorf("expected RTO floored at %v, got %v", prober.DefaultMinRTO, r)
	}

	// RFC 6298: RTO = SRTT + max(G, 4*RTTVAR). On a zero-jitter link
	// RTTVAR decays below G/4, so the clock granularity term takes over.
	stats.Update(0.050)
	for i := 0; i < 25; i++ {
		stats.Update(0.050)
	}
	wantG := 0.050 + prober.DefaultClockGranularity.Seconds()
	if math.Abs(stats.RTO()-wantG) > 0.0005 {
		t.Errorf("expected RTO = SRTT + max(G, 4*RTTVAR) ≈ %f, got %f", wantG, stats.RTO())
	}

	// RTTVAR term dominates when jitter is large: 4*RTTVAR > G.
	stats.Update(0.200)
	expect := stats.SRTT() + 4*stats.RTTVar()
	if stats.RTO() < expect-0.0001 {
		t.Errorf("RTO must include 4*RTTVAR term, got %f < %f", stats.RTO(), expect)
	}
}

func TestAdaptive_RespondsToJitter(t *testing.T) {
	prober.InitMetrics()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	var delay atomicLatency
	delay.set(10 * time.Millisecond)

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
			time.Sleep(delay.get())
			conn.Write(buf)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(true, 50*time.Millisecond, 500*time.Millisecond, prober.Target{Name: "adaptive_jitter", Address: addr})
	go prober.RunClient(ctx, cfg)

	time.Sleep(1 * time.Second)
	rtoLow := getGaugeValue(prober.RTOEstimate, "adaptive_jitter", addr)

	delay.set(150 * time.Millisecond)
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
