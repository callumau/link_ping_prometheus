package prober_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"tcp_ping_prometheus/internal/prober"
)

func TestGarbageData_Server(t *testing.T) {
	prober.InitMetrics()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, err := conn.Write([]byte("garbage data garbage data garbage data\n"))
			if err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	targetName := "garbage_test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cfgWith(false, 100*time.Millisecond, 100*time.Millisecond, prober.Target{Name: targetName, Address: addr})
	startRecv := getCounterValue(prober.ReceivedTotal, targetName, addr)

	go prober.RunClient(ctx, cfg)
	time.Sleep(500 * time.Millisecond)
	cancel()

	endRecv := getCounterValue(prober.ReceivedTotal, targetName, addr)
	if endRecv > startRecv {
		t.Errorf("Garbage data counted as valid response? %v -> %v", startRecv, endRecv)
	}
}

func TestServer_EnforceSizeAndHeader(t *testing.T) {
	prober.InitMetrics()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go prober.ServeListener(ctx, ln)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 34)
	copy(buf[0:8], prober.MagicBytes)
	_, err = conn.Write(buf)
	if err != nil {
		t.Fatal(err)
	}

	reply := make([]byte, 24)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("Should have received echo for first valid part: %v", err)
	}
	if string(reply[0:8]) != prober.MagicBytes {
		t.Errorf("Reply header invalid")
	}

	conn.Close()
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf = make([]byte, 48)
	copy(buf[0:8], prober.MagicBytes)
	copy(buf[24:32], "BADHEADR")
	conn.Write(buf)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, reply)
	if err != nil {
		t.Fatalf("Should get 1st reply: %v", err)
	}

	_, err = io.ReadFull(conn, reply)
	if err == nil {
		t.Errorf("Expected server to close connection on invalid 2nd packet header, but got reply")
	} else {
		t.Logf("Got expected error on 2nd packet: %v", err)
	}
}
