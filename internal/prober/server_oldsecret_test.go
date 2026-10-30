package prober

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// -echo-secret-old handling. main.go always passes the flag as a ONE-element
// variadic, so "no rotation configured" reaches the server as
// echoSecretOld[0] == "". A zero-length key is a perfectly valid HMAC key, so
// an unguarded newProbeMACer("") installs a verifier for HMAC-SHA256(key "")
// and ANY off-path host can tag its own frames: the server echoes them
// (reflection) and spends the victim IP's per-IP budget, while the server looks
// correctly configured. The empty case must therefore be rejected at the guard,
// not tolerated downstream.

// oldSecretServerAddr starts a real ServePacketConn on an ephemeral loopback
// port with the secret arguments exactly as main.go passes them (old secrets
// variadic, empty string included).
func oldSecretServerAddr(t *testing.T, ctx context.Context, source, secret string, old ...string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := ParseAllowlist("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServePacketConn(ctx, pc, source, allowed, secret, old...)
	}()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	t.Cleanup(func() {
		// Close the socket here rather than waiting for ctx: a caller that
		// passes a parent test's context would otherwise join a server whose
		// cancel only fires after the subtests finish. Close is idempotent
		// with the ctx watcher above.
		pc.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("echo server did not stop after socket close")
		}
	})
	return pc.LocalAddr().String()
}

// oldSecretDial opens a UDP conn to addr, closed at test end.
func oldSecretDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// oldSecretSend writes frame and returns the echoed byte count (0 when the
// server dropped it). The deadline covers the server's whole handling path.
func oldSecretSend(t *testing.T, conn net.Conn, frame []byte) int {
	t.Helper()
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	n, _ := conn.Read(make([]byte, MaxDatagramSize))
	return n
}

// oldSecretHeaderFrame is a bare 32-byte frame carrying the header tag (the
// v0.7 coverage) computed under key.
func oldSecretHeaderFrame(seq, ts uint64, key string) []byte {
	f := make([]byte, PayloadSizeWithHMAC)
	copy(f[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(f[8:16], seq)
	binary.LittleEndian.PutUint64(f[16:24], ts)
	tag := headerTag(key, seq, ts)
	copy(f[24:32], tag[:])
	return f
}

// oldSecretFullFrame is a 32-byte header plus payload frame carrying the
// full-frame tag under key — the shape a -hmac-coverage=full-frame client
// emits, i.e. the frame whose tag slot a captured-tag forgery would occupy.
func oldSecretFullFrame(seq, ts uint64, key string, payloadLen int) []byte {
	f := make([]byte, PayloadSizeWithHMAC+payloadLen)
	copy(f[0:8], MagicBytes)
	binary.LittleEndian.PutUint64(f[8:16], seq)
	binary.LittleEndian.PutUint64(f[16:24], ts)
	for i := PayloadSizeWithHMAC; i < len(f); i++ {
		f[i] = byte(i * 31)
	}
	tag := frameTag(key, f)
	copy(f[24:32], tag[:])
	return f
}

// TestServer_EmptyOldSecretIsNotAKey: an empty -echo-secret-old must install
// no verifier. Each case runs its own server with its own {source} label, so
// the drop counters are asserted absolutely rather than as shared deltas.
func TestServer_EmptyOldSecretIsNotAKey(t *testing.T) {
	InitMetrics()
	ctx := t.Context()

	const primary, previous = "rot-primary-secret", "rot-previous-secret"
	now := func() uint64 { return uint64(time.Now().UnixNano()) }
	hmacDrops := func(source string) float64 {
		return hmacCounter(ServerProbesDropped, source, "hmac")
	}

	t.Run("empty old secret: empty-key header tag is dropped", func(t *testing.T) {
		const source = "oldsecret-empty-header"
		conn := oldSecretDial(t, oldSecretServerAddr(t, ctx, source, primary, ""))

		if n := oldSecretSend(t, conn, oldSecretHeaderFrame(1, now(), primary)); n != PayloadSizeWithHMAC {
			t.Fatalf("primary-secret frame must be echoed (control), got %d bytes", n)
		}
		if n := oldSecretSend(t, conn, oldSecretHeaderFrame(2, now(), "")); n != 0 {
			t.Errorf("a frame tagged with the EMPTY key must be dropped, got %d bytes echoed back (reflection)", n)
		}
		if got := hmacDrops(source); got != 1 {
			t.Errorf("the empty-key frame must count as an hmac drop, got %v", got)
		}
	})

	t.Run("rotation: current and previous tags both accepted", func(t *testing.T) {
		const source = "oldsecret-rotation"
		conn := oldSecretDial(t, oldSecretServerAddr(t, ctx, source, primary, previous))

		if n := oldSecretSend(t, conn, oldSecretHeaderFrame(1, now(), primary)); n != PayloadSizeWithHMAC {
			t.Errorf("current-secret frame must be echoed, got %d bytes", n)
		}
		if n := oldSecretSend(t, conn, oldSecretHeaderFrame(2, now(), previous)); n != PayloadSizeWithHMAC {
			t.Errorf("previous-secret frame must be echoed during a rotation, got %d bytes", n)
		}
		if got := hmacDrops(source); got != 0 {
			t.Errorf("a valid rotation pair must drop nothing, got %v hmac drops", got)
		}
	})

	t.Run("empty old secret: empty-key full-frame tag on a payload frame is dropped", func(t *testing.T) {
		const source = "oldsecret-empty-fullframe"
		const payloadLen = 64
		conn := oldSecretDial(t, oldSecretServerAddr(t, ctx, source, primary, ""))

		good := oldSecretFullFrame(1, now(), primary, payloadLen)
		if n := oldSecretSend(t, conn, good); n != len(good) {
			t.Fatalf("primary-secret full-frame payload probe must be echoed (control), got %d of %d bytes", n, len(good))
		}
		bad := oldSecretFullFrame(2, now(), "", payloadLen)
		if n := oldSecretSend(t, conn, bad); n != 0 {
			t.Errorf("a full-frame tag under the EMPTY key must be dropped, got %d bytes echoed back (reflection)", n)
		}
		if got := hmacDrops(source); got != 1 {
			t.Errorf("the empty-key full-frame tag must count as an hmac drop, got %v", got)
		}
	})
}
