package prober

import (
	"net"
	"testing"
	"time"
)

// The dup guard must run AHEAD of the per-IP charge and key on the source IP
// WITHOUT the source port. One captured authenticated frame replayed at a
// victim's source IP would otherwise (a) spend that IP's whole per-second
// budget, so the real client's probes read 100% loss for the rest of the
// window, and (b) look like a fresh identity on every rotating source port, so
// the guard never saw it at all.

func TestServer_ReplayedFrameDoesNotSpendPerIPBudget(t *testing.T) {
	InitMetrics()
	const source, secret, perIPCap = "dupbudget", "dupbudget-secret", 2
	// The per-IP cap is read when ServePacketConn builds its limiter, so set
	// it before starting the server and restore it afterwards.
	oldCap := MaxPktsPerIP
	MaxPktsPerIP = perIPCap
	t.Cleanup(func() { MaxPktsPerIP = oldCap })

	ctx := t.Context()
	addr := oldSecretServerAddr(t, ctx, source, secret)
	conn := oldSecretDial(t, addr)

	dupDrops := func() float64 { return hmacCounter(ServerProbesDropped, source, "dup") }
	rateIPDrops := func() float64 { return hmacCounter(ServerProbesDropped, source, "rate_ip") }

	captured := oldSecretHeaderFrame(1, uint64(time.Now().UnixNano()), secret)
	if n := oldSecretSend(t, conn, captured); n != PayloadSizeWithHMAC {
		t.Fatalf("the original frame must be echoed, got %d bytes", n)
	}
	// That echo spent one of the perIPCap units; the remainder is what the
	// replay burst below must not touch.

	// Replay the SAME frame from distinct source ports: a fresh Dial gets a
	// fresh local port, which is exactly the laundering the port-keyed
	// identity allowed. None of these may echo.
	replays := 2 * perIPCap
	for i := 0; i < replays; i++ {
		rc, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rc.Write(captured); err != nil {
			_ = rc.Close()
			t.Fatalf("replay %d write: %v", i, err)
		}
		_ = rc.Close()
	}

	// The replays travel on their own sockets, so wait for the counter rather
	// than assuming the server has drained them all.
	deadline := time.Now().Add(2 * time.Second)
	for dupDrops() < float64(replays) && time.Now().Before(deadline) {
		// pi-lens-ignore: go-time-sleep-test
		time.Sleep(5 * time.Millisecond)
	}
	if got := dupDrops(); got != float64(replays) {
		t.Errorf("every replay must be dropped as a dup, got %v of %d", got, replays)
	}
	if got := rateIPDrops(); got != 0 {
		t.Errorf("a dup must not be charged to the per-IP budget, got %v rate_ip drops", got)
	}

	// The budget the replays would have spent must still be intact: a fresh
	// probe from the same IP authenticates and is echoed.
	fresh := oldSecretHeaderFrame(2, uint64(time.Now().UnixNano()), secret)
	if n := oldSecretSend(t, conn, fresh); n != PayloadSizeWithHMAC {
		t.Errorf("a fresh probe must still be echoed after the replay burst, got %d bytes (budget consumed by dups)", n)
	}
}
