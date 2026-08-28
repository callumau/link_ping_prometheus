package prober_test

import (
	"context"
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// udpEcho starts a UDP responder on an ephemeral port with a
// per-datagram handler, returning its address. The handler receives each
// datagram and may call w to send a reply; it runs serially in the read
// loop (delays in the handler delay all subsequent echoes).
func udpEcho(t *testing.T, ctx context.Context, handle func(buf []byte, w func([]byte))) string {
	t.Helper()
	pc := listenUDP(t, ctx)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			handle(buf[:n], func(reply []byte) {
				pc.WriteTo(reply, raddr)
			})
		}
	}()
	return pc.LocalAddr().String()
}

// echoAll echoes every 24-byte validated probe untouched.
func echoAll(buf []byte, w func([]byte)) {
	if len(buf) != prober.PayloadSize || string(buf[0:8]) != prober.MagicBytes {
		return
	}
	w(buf)
}

// TestOutage_NaturalLoss: with no server at the target, every probe is
// sent into the void and times out naturally (UDP never retransmits), so
// the loss ratio reads ~100% — no fabricated counters needed.
func TestOutage_NaturalLoss(t *testing.T) {
	prober.InitMetrics()

	// Fixed (non-ephemeral) address, so the metric series persists across
	// -count>1 runs in the same process: read baselines, never absolute
	// counter values, or repeated runs accumulate on the same series.
	addr := "127.0.0.1:1" // nothing listening: datagrams vanish
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 100*time.Millisecond, 100*time.Millisecond, prober.Target{Name: "outage_test", Address: addr})

	startSent := getCounterValue(prober.ProbesSent, "outage_test", addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, "outage_test", addr)

	runClientFor(ctx, cfg, 500*time.Millisecond)
	cancel()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(200 * time.Millisecond)

	sent := getCounterValue(prober.ProbesSent, "outage_test", addr) - startSent
	timeout := getCounterValue(prober.ProbesTimedOut, "outage_test", addr) - startTimeout

	if sent < 2 {
		t.Errorf("Expected probes to be sent into the void, got %v", sent)
	}
	if timeout < 2 {
		t.Errorf("Expected natural timeouts without a server, got %v", timeout)
	}
	// Tolerance 3 bounds the probes abandoned in flight at cancel (never
	// flushed to timeouts by design — see TestGracefulShutdown): with
	// interval == timeout == 100ms a probe survives until a tick sees it
	// strictly past the RTO, so up to ~3 can be pending at the cancel
	// instant. They are shutdown bookkeeping, not loss.
	if math.Abs(sent-timeout) > 3 {
		t.Errorf("Outage loss must read ~100%%: sent %v, timeout %v", sent, timeout)
	}
	if inflight := getGaugeValue(prober.ProbesInflight, "outage_test", addr); inflight != 0 {
		t.Errorf("In-flight must drain to 0, got %v", inflight)
	}
	if up := getGaugeValue(prober.LinkUp, "outage_test", addr); up != 0 {
		t.Errorf("Link must stay down, got %v", up)
	}
}

func TestAccuracy_PacketLoss(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dropRate := 3
	totalPackets := 10

	count := 0
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		dropEvery(&count, dropRate, buf, w)
	})

	targetName, cfg := namedCfg("loss_accuracy_test", addr, 50*time.Millisecond, 100*time.Millisecond)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	runClientFor(ctx, cfg, time.Duration(totalPackets+2)*50*time.Millisecond)
	cancel()

	// pi-lens-ignore: go-time-sleep-test

	time.Sleep(200 * time.Millisecond)

	endSent := getCounterValue(prober.ProbesSent, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	sentCount := endSent - startSent
	timeoutCount := endTimeout - startTimeout

	if sentCount < float64(totalPackets) {
		t.Logf("Warning: Sent less packets than intended (%v < %v), cpu load?", sentCount, totalPackets)
	}

	expectedDrops := int(sentCount) / dropRate

	if math.Abs(timeoutCount-float64(expectedDrops)) > 1.5 {
		t.Errorf("Expected approx %d timeouts (sent %d, rate 1/%d), got %v", expectedDrops, int(sentCount), dropRate, timeoutCount)
	}
}

func TestAccuracy_HighLatency(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delay := 150 * time.Millisecond

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(delay)
		w(buf)
	})

	targetName := "latency_test"
	cfg := cfgWith(true, 300*time.Millisecond, 50*time.Millisecond, prober.Target{Name: targetName, Address: addr})
	runClientFor(ctx, cfg, 1500*time.Millisecond)

	rttVal := getHistogramMean(prober.RTTSeconds, targetName, addr)

	if rttVal < delay.Seconds()-0.02 || rttVal > delay.Seconds()+0.05 {
		t.Errorf("RTT Accuracy mismatch: expected ~%vs, got %vs", delay.Seconds(), rttVal)
	}
}

// pi-lens-ignore: jscpd:duplicate
func TestRobustness_CorruptSeq(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		corrupt := append([]byte(nil), buf...)
		// Corrupt the sequence-number field only; the magic stays valid,
		// so the frame passes the header check and must be rejected by
		// the pending-sequence lookup (previously this loop flipped the
		// magic bytes, testing header rejection, not seq corruption).
		for i := 8; i < 16; i++ {
			corrupt[i] = ^corrupt[i]
		}
		w(corrupt)
	})

	// pi-lens-ignore: jscpd:duplicate
	targetName, cfg := namedCfg("corrupt_test", addr, 50*time.Millisecond, 100*time.Millisecond)

	startRecv, startTimeout := recvTimeoutCounters(targetName, addr)

	runClientSettle(ctx, cancel, cfg, 500*time.Millisecond)

	endRecv, endTimeout := recvTimeoutCounters(targetName, addr)

	if endRecv > startRecv {
		t.Errorf("Client should not have accepted corrupt packets, but Recv increased by %v", endRecv-startRecv)
	}
	if endTimeout <= startTimeout {
		t.Errorf("Client should have timed out on corrupt packets, but Timeout did not increase")
	}
}

func TestRobustness_StalledServer(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Read and never answer.
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {})

	targetName, cfg := namedCfg("stall_test", addr, 50*time.Millisecond, 50*time.Millisecond)

	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	runClientFor(ctx, cfg, 500*time.Millisecond)
	cancel()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(100 * time.Millisecond)

	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	if endTimeout-startTimeout < 4 {
		t.Errorf("Expected significant timeouts during stall, got %v", endTimeout-startTimeout)
	}
}

func TestAccuracy_KnownLatencyAndLoss(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	delay := 17 * time.Millisecond
	dropMod := 4
	// Drop every 4th of the first dropWindow packets, echo everything
	// after that. All drops then age past the client timeout well before
	// measurement, so the expected count is exact and independent of
	// cancel-time in-flight state.
	dropWindow := 24

	count := 0
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		count++
		if count <= dropWindow && count%dropMod == 0 {
			return
		}
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(delay)
		w(buf)
	})

	targetName, cfg := namedCfg("latency_loss_test", addr, 50*time.Millisecond, 500*time.Millisecond)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	// dropWindow packets take ~1.2s; their drops are all swept by ~1.7s.
	// 2.5s leaves ample margin under CI load.
	runClientFor(ctx, cfg, 2500*time.Millisecond)
	cancel()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(200 * time.Millisecond)

	endSent := getCounterValue(prober.ProbesSent, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	rttVal := getHistogramMean(prober.RTTSeconds, targetName, addr)

	sentCount := endSent - startSent
	timeoutCount := endTimeout - startTimeout

	if sentCount < float64(dropWindow) {
		t.Fatalf("Sent fewer probes (%v) than the drop window (%d) — cpu load?", sentCount, dropWindow)
	}

	expectedDrops := dropWindow / dropMod
	if math.Abs(timeoutCount-float64(expectedDrops)) > 0.5 {
		t.Errorf("Loss accuracy mismatch: expected exactly %d timeouts (1/%d of first %d), got %v", expectedDrops, dropMod, dropWindow, timeoutCount)
	}

	if rttVal < delay.Seconds()-0.003 || rttVal > delay.Seconds()+0.015 {
		t.Errorf("RTT accuracy mismatch: expected ~%vs (delay %v), got %vs", delay.Seconds(), delay, rttVal)
	}
}

// pi-lens-ignore: jscpd:duplicate
func TestDuplicateResponse(t *testing.T) {
	// pi-lens-ignore: jscpd:duplicate
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		w(buf)
		w(buf)
	})

	targetName, cfg := namedCfg("duplicate_test", addr, 100*time.Millisecond, 500*time.Millisecond)

	startRecv, startSent := recvSentCounters(targetName, addr)

	runClientFor(ctx, cfg, 500*time.Millisecond)
	cancel()

	endRecv, endSent := recvSentCounters(targetName, addr)

	recvDelta := endRecv - startRecv
	sentDelta := endSent - startSent

	// Vacuous-pass guard: without probes the assertion below is trivially true.
	if sentDelta < 1 {
		t.Fatalf("client sent no probes; duplicate-counting not exercised (cpu load?)")
	}

	if recvDelta > sentDelta+1 {
		t.Errorf("Duplicate responses counted! Sent %v, Recv %v", sentDelta, recvDelta)
	}
}

// TestRobustness_TimestampSpoof: responses with a valid seq but a tampered
// payload timestamp must be rejected (left to time out as loss), guarding
// RTT samples against corruption/replay/spoofing.
// pi-lens-ignore: jscpd:duplicate
func TestRobustness_TimestampSpoof(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		tampered := append([]byte(nil), buf...)
		tampered[16] ^= 0xFF // tamper with the echoed timestamp
		w(tampered)
	})

	// pi-lens-ignore: jscpd:duplicate
	targetName, cfg := namedCfg("spoof_ts_test", addr, 50*time.Millisecond, 100*time.Millisecond)

	startRecv, startTimeout := recvTimeoutCounters(targetName, addr)

	runClientSettle(ctx, cancel, cfg, 500*time.Millisecond)

	endRecv, endTimeout := recvTimeoutCounters(targetName, addr)

	if endRecv > startRecv {
		t.Errorf("Client accepted responses with tampered timestamps: Recv increased by %v", endRecv-startRecv)
	}
	if endTimeout <= startTimeout {
		t.Errorf("Tampered responses should time out as loss, but Timeout did not increase")
	}
}

// TestRobustness_OutOfOrderResponses: the echo server must be able to
// return responses in a different order than sent (groups of three
// reversed). Every response must still be matched by sequence number,
// counted once, and no timeouts may be attributed to reordering.
func TestRobustness_OutOfOrderResponses(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	group := make([][]byte, 0, 3)
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		group = append(group, append([]byte(nil), buf...))
		if len(group) == 3 {
			for i := 2; i >= 0; i-- {
				w(group[i])
			}
			group = group[:0]
		}
	})

	targetName, cfg := namedCfg("reorder_test", addr, 50*time.Millisecond, 300*time.Millisecond)

	startRecv, startTimeout := recvTimeoutCounters(targetName, addr)

	runClientFor(ctx, cfg, 900*time.Millisecond)
	cancel()

	endRecv, endTimeout := recvTimeoutCounters(targetName, addr)

	if endRecv-startRecv < 5 {
		t.Errorf("Out-of-order responses should all be matched by seq: received %v", endRecv-startRecv)
	}
	if endTimeout != startTimeout {
		t.Errorf("Reordering must not cause timeouts: %v -> %v", startTimeout, endTimeout)
	}
	if rtt := getHistogramMean(prober.RTTSeconds, targetName, addr); rtt <= 0 {
		t.Errorf("RTT must stay positive under reordering, got %v", rtt)
	}
}

// TestRobustness_DuplicateWithTamperedCopy: a valid echo followed
// immediately by a copy with a tampered timestamp must count exactly
// once — the second copy must be rejected, not double-counted or
// counted as a different response.
// pi-lens-ignore: jscpd:duplicate
func TestRobustness_DuplicateWithTamperedCopy(t *testing.T) {
	// pi-lens-ignore: jscpd:duplicate
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		w(buf)
		tampered := append([]byte(nil), buf...)
		tampered[16] ^= 0xFF
		w(tampered)
	})

	// pi-lens-ignore: jscpd:duplicate
	targetName, cfg := namedCfg("dup_tamper_test", addr, 50*time.Millisecond, 300*time.Millisecond)

	startRecv, startSent := recvSentCounters(targetName, addr)

	runClientFor(ctx, cfg, 600*time.Millisecond)
	cancel()

	recvDelta := getHistogramCount(prober.RTTSeconds, targetName, addr) - startRecv
	sentDelta := getCounterValue(prober.ProbesSent, targetName, addr) - startSent

	if math.Abs(recvDelta-sentDelta) > 1 {
		t.Errorf("Tampered duplicate copies must not count: sent %v, received %v", sentDelta, recvDelta)
	}
}

// TestRobustness_LateResponsesIgnored: responses arriving after their
// probe already timed out must be silently dropped — never counted as
// received, never disrupting the probe loop.
func TestRobustness_LateResponsesIgnored(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Echo everything, but 250ms late — beyond the 100ms client timeout.
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(250 * time.Millisecond)
		w(buf)
	})

	targetName, cfg := namedCfg("late_test", addr, 50*time.Millisecond, 100*time.Millisecond)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	startRecv := getHistogramCount(prober.RTTSeconds, targetName, addr)

	runClientFor(ctx, cfg, 600*time.Millisecond)
	cancel()

	sentDelta := getCounterValue(prober.ProbesSent, targetName, addr) - startSent
	timeoutDelta := getCounterValue(prober.ProbesTimedOut, targetName, addr) - startTimeout
	recvDelta := getHistogramCount(prober.RTTSeconds, targetName, addr) - startRecv

	if sentDelta < 6 {
		t.Errorf("Expected probes to keep flowing through late responses, got %v", sentDelta)
	}
	if timeoutDelta < 3 {
		t.Errorf("Expected late responses to be counted as timeouts, got %v", timeoutDelta)
	}
	if recvDelta != 0 {
		t.Errorf("Late responses must never count as received, got %v", recvDelta)
	}
}

// TestRobustness_SpuriousValidFrames: frames with a valid magic header
// but a sequence number the client never sent must be ignored — they
// must not inflate the received counter or disturb in-flight probes.
// pi-lens-ignore: jscpd:duplicate
func TestRobustness_SpuriousValidFrames(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		w(buf)
		// Valid magic + valid-looking ts, but a seq the client
		// could not have sent (client seqs start at 1 and grow).
		spurious := append([]byte(nil), buf...)
		binary.LittleEndian.PutUint64(spurious[8:16], math.MaxUint64)
		w(spurious)
	})

	// pi-lens-ignore: jscpd:duplicate
	targetName, cfg := namedCfg("spurious_test", addr, 50*time.Millisecond, 300*time.Millisecond)

	startRecv, startSent := recvSentCounters(targetName, addr)

	runClientFor(ctx, cfg, 600*time.Millisecond)
	cancel()

	recvDelta := getHistogramCount(prober.RTTSeconds, targetName, addr) - startRecv
	sentDelta := getCounterValue(prober.ProbesSent, targetName, addr) - startSent

	if math.Abs(recvDelta-sentDelta) > 1 {
		t.Errorf("Spurious frames must be ignored: sent %v, received %v", sentDelta, recvDelta)
	}
}

// TestIsolation_BrokenTargetDoesNotAffectHealthy: a dead link and a
// healthy link monitored together must not contaminate each other's
// metrics — the healthy link keeps probing while the broken one
// accumulates natural timeouts.
func TestIsolation_BrokenTargetDoesNotAffectHealthy(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	healthyAddr := startEchoServer(ctx, t)
	deadAddr := "127.0.0.1:1" // nothing listening: probes vanish

	targets := []prober.Target{
		{Name: "healthy", Address: healthyAddr},
		{Name: "broken", Address: deadAddr},
	}
	cfg := cfgWith(false, 100*time.Millisecond, 500*time.Millisecond, targets...)

	runClientFor(ctx, cfg, time.Second)

	if recv := getHistogramCount(prober.RTTSeconds, "healthy", healthyAddr); recv <= 0 {
		t.Errorf("Healthy link should receive probes, got %v", recv)
	}
	if up := getGaugeValue(prober.LinkUp, "healthy", healthyAddr); up != 1 {
		t.Errorf("Healthy link must be up, got %v", up)
	}

	if up := getGaugeValue(prober.LinkUp, "broken", deadAddr); up != 0 {
		t.Errorf("Broken link must be down, got %v", up)
	}
}

// TestInflight_ClimbsOnStallThenDrains: link_probes_inflight must grow
// while responses are withheld (the deadlock-detection signal) and
// return to zero on cancellation, clean or otherwise.
func TestInflight_ClimbsOnStallThenDrains(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())

	// Read but never respond.
	addr := udpEcho(t, ctx, func(buf []byte, w func([]byte)) {})

	targetName := "inflight_stall_test"

	// Long timeout relative to interval: nothing ever resolves, so the
	// in-flight count must climb while the stall lasts.
	cfg := cfgWith(false, 50*time.Millisecond, 5*time.Second, prober.Target{Name: targetName, Address: addr})
	runClientFor(ctx, cfg, 500*time.Millisecond)
	if got := getGaugeValue(prober.ProbesInflight, targetName, addr); got < 5 {
		t.Errorf("In-flight probes should climb during a stall, got %v", got)
	}

	cancel()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(300 * time.Millisecond)

	if got := getGaugeValue(prober.ProbesInflight, targetName, addr); got != 0 {
		t.Errorf("In-flight must drain to 0 after cancellation, got %v", got)
	}
}

// TestGracefulShutdown_NoPhantomTimeouts: probes still in flight when the
// context is cancelled must NOT be flushed into ProbesTimedOut — otherwise
// every deploy/restart injects phantom packet loss.
func TestGracefulShutdown_NoPhantomTimeouts(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())

	// Echo only after 1s — far beyond the test window — so probes stay
	// in flight at cancel time without ever timing out (client timeout 5s).
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(1 * time.Second)
		w(buf)
	})

	targetName, cfg := namedCfg("graceful_test", addr, 50*time.Millisecond, 5*time.Second)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	runClientFor(ctx, cfg, 300*time.Millisecond)
	cancel()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(300 * time.Millisecond)

	endSent := getCounterValue(prober.ProbesSent, targetName, addr)
	endTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	if endSent <= startSent {
		t.Fatalf("Expected probes to be sent, got %v -> %v", startSent, endSent)
	}
	if endTimeout != startTimeout {
		t.Errorf("Graceful shutdown must not flush in-flight probes to timeouts: %v -> %v", startTimeout, endTimeout)
	}
}

// TestLinkUp_RequiresThreeMisses: link_up must not flap on a single lost
// probe, but must drop to 0 after LinkUpMissThreshold consecutive probes
// time out (enterprise health-check convention).
func TestLinkUp_RequiresThreeMisses(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dropOne atomic.Bool
	dropOne.Store(true)
	halt := make(chan struct{})
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		select {
		case <-halt:
			return
		default:
		}
		if dropOne.CompareAndSwap(true, false) {
			return // single missed probe
		}
		w(buf)
	})

	targetName, cfg := namedCfg("linkup_test", addr, 50*time.Millisecond, 100*time.Millisecond)
	// A single dropped probe must not take the link down.
	runClientFor(ctx, cfg, 400*time.Millisecond)
	if up := getGaugeValue(prober.LinkUp, targetName, addr); up != 1 {
		t.Errorf("single missed probe must not flap link_up, got %v", up)
	}

	// Stop echoing entirely: down after LinkUpMissThreshold misses.
	close(halt)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if up := getGaugeValue(prober.LinkUp, targetName, addr); up == 0 {
			break
		}
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(50 * time.Millisecond)
	}
	if up := getGaugeValue(prober.LinkUp, targetName, addr); up != 0 {
		t.Errorf("link_up must drop after %d consecutive missed probes, got %v", prober.LinkUpMissThreshold, up)
	}
}

// dropEvery is a stateful wrapper that drops every Nth probe and echoes
// the rest. Kept as a closure helper so accuracy tests can share it.
func dropEvery(count *int, n int, buf []byte, w func([]byte)) {
	*count++
	if *count%n == 0 {
		return
	}
	w(buf)
}

// TestAccuracy_PacketLoss10s: over a sustained 10s+ window the client's
// loss ratio must track the server's drop rate. The server reads every
// probe but echoes only a fraction (dropping every 3rd), so no TCP
// retransmission is involved — this isolates the client's counter
// pi-lens-ignore: typos, typos:unknown
// accounting. Adaptive RTO changes when timeouts are detected, not the
// total count, so the ratio must converge to the injected drop rate.
func TestAccuracy_PacketLoss10s(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())

	count := 0
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		dropEvery(&count, 3, buf, w)
	})

	targetName := "loss_10s_test"
	cfg := cfgWith(true, 100*time.Millisecond, 400*time.Millisecond, prober.Target{Name: targetName, Address: addr})
	runClientFor(ctx, cfg, 12*time.Second)
	cancel()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(200 * time.Millisecond)

	sent := getCounterValue(prober.ProbesSent, targetName, addr)
	timeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	recv := getHistogramCount(prober.RTTSeconds, targetName, addr)

	if sent < 80 {
		t.Fatalf("Expected ~120 probes over 12s at 100ms interval, got %v (cpu load?)", sent)
	}

	got := timeout / sent
	want := 1.0 / 3.0
	if math.Abs(got-want) > 0.06 {
		t.Errorf("Loss over 10s+ window: expected ~%v, got %v (sent %v, timeout %v)", want, got, sent, timeout)
	}

	inflight := getGaugeValue(prober.ProbesInflight, targetName, addr)
	// Cancel abandons up to a few in-flight probes uncounted (graceful
	// shutdown semantics), so the residual must tolerate that population.
	if math.Abs(sent-recv-timeout-inflight) > 3 {
		t.Errorf("Counter balance broken: sent=%v recv=%v timeout=%v inflight=%v",
			sent, recv, timeout, inflight)
	}
}

// TestReconnect_KeepsProbingAndBalance: with a short reconnect interval
// the client must re-dial repeatedly (re-resolving DNS) without losing or
// fabricating any probe — the sent/rtt/timedout/inflight balance holds
// across every reconnect, and probes keep flowing to a healthy target.
func TestRobustness_DuplicateStormBalance(t *testing.T) {
	prober.InitMetrics()
	// pi-lens-ignore: go-context-background-handler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var prev []byte
	addr := validatedEcho(t, ctx, func(buf []byte, w func([]byte)) {
		w(buf)
		w(buf)
		w(buf)
		mu.Lock()
		defer mu.Unlock()
		if prev != nil {
			w(prev) // stale replay of an already-matched sequence number
		}
		prev = append([]byte(nil), buf...)
	})

	// Timeout longer than the run so nothing expires: every sent probe
	// ends matched-once or still pending, making the balance equation
	// exact rather than approximate.
	targetName, cfg := namedCfg("dup_storm_test", addr, 50*time.Millisecond, 2*time.Second)

	startSent := getCounterValue(prober.ProbesSent, targetName, addr)
	startRecv := getHistogramCount(prober.RTTSeconds, targetName, addr)
	startTimeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)

	runClientSettle(ctx, cancel, cfg, 700*time.Millisecond)

	sentDelta := getCounterValue(prober.ProbesSent, targetName, addr) - startSent
	recvDelta := getHistogramCount(prober.RTTSeconds, targetName, addr) - startRecv
	timeoutDelta := getCounterValue(prober.ProbesTimedOut, targetName, addr) - startTimeout
	inflight := getGaugeValue(prober.ProbesInflight, targetName, addr)

	if sentDelta < 5 {
		t.Fatalf("run too short to exercise the duplicate storm, sent=%v", sentDelta)
	}
	if recvDelta > sentDelta {
		t.Errorf("duplicates counted as extra receives: sent=%v recv=%v", sentDelta, recvDelta)
	}
	if timeoutDelta != 0 {
		t.Errorf("no probe should expire inside a %v window, timed_out grew by %v", cfg.BaseTimeout, timeoutDelta)
	}
	// Exact balance modulo the documented cancel-instant abandonment
	// (graceful shutdown neither receives nor times out probes still in
	// flight — see TestGracefulShutdown_NoPhantomTimeouts); at a 50ms
	// interval that is at most ~2 probes.
	if lost := sentDelta - recvDelta - timeoutDelta - inflight; lost > 2 {
		t.Errorf("balance broken under duplicate storm: sent=%v recv=%v timeout=%v inflight=%v (lost=%v)",
			sentDelta, recvDelta, timeoutDelta, inflight, lost)
	}
}

// TestReconnect_KeepsProbingAndBalance: with a short reconnect interval
// the client must re-dial repeatedly (re-resolving DNS) without losing or
// fabricating any probe — the sent/rtt/timedout/inflight balance holds
// across every reconnect, and probes keep flowing to a healthy target.
func TestReconnect_KeepsProbingAndBalance(t *testing.T) {
	prober.InitMetrics()
	old := prober.ReconnectInterval
	prober.ReconnectInterval = 200 * time.Millisecond
	defer func() { prober.ReconnectInterval = old }()

	// pi-lens-ignore: go-context-background-handler

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := startEchoServer(ctx, t)
	targetName := "reconnect_test"
	cfg := cfgWith(false, 50*time.Millisecond, 500*time.Millisecond, prober.Target{Name: targetName, Address: addr})

	go prober.RunClient(ctx, cfg)
	// Span several reconnect cycles (200ms each).
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(1500 * time.Millisecond)
	cancel()
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(200 * time.Millisecond)

	sent := getCounterValue(prober.ProbesSent, targetName, addr)
	timeout := getCounterValue(prober.ProbesTimedOut, targetName, addr)
	recv := getHistogramCount(prober.RTTSeconds, targetName, addr)
	inflight := getGaugeValue(prober.ProbesInflight, targetName, addr)

	if sent < 10 {
		t.Errorf("probes must keep flowing across reconnects, sent=%v", sent)
	}
	if inflight != 0 {
		t.Errorf("inflight must drain to 0 after cancel, got %v", inflight)
	}
	// Balance must hold across every reconnect. The only allowed
	// residual is the probe(s) still in flight at the cancel instant:
	// graceful shutdown abandons them (neither received, timed out, nor
	// counted in the drained inflight gauge) — the behaviour
	// TestGracefulShutdown_NoPhantomTimeouts asserts. At a 50ms interval
	// that is at most ~2 probes; a reconnect bug would abandon ~1 probe
	// per 200ms cycle (≈7 here), so the threshold cleanly separates.
	lost := sent - recv - timeout - inflight
	if lost > 2 {
		t.Errorf("counter balance broken across reconnects: sent=%v recv=%v timeout=%v inflight=%v (lost=%v)",
			sent, recv, timeout, inflight, lost)
	}
}
