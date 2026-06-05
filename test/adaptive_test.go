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
