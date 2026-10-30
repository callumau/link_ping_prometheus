package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"link_ping_prometheus/internal/prober"
)

// TestReadyzSemantics pins the liveness/readiness split: /healthz stays
// always-200, while /readyz must report 503 for a client-side agent that has
// never held a working socket (DNS outage, firewall) - alive but probing
// nothing is exactly the failure mode an orchestrator must be able to see.
// socket_age_seconds is set only after a successful dial, so it is the signal
// the gate reads.
func TestReadyzSemantics(t *testing.T) {
	// A target still in the dial-retry loop publishes a target entry with
	// socket_age_seconds == 0; one with a live socket publishes > 0.
	dialStuck := []prober.TargetStatus{{Name: "a"}}
	working := []prober.TargetStatus{{Name: "a"}, {Name: "b", SocketAgeSeconds: 12.5}}

	tests := []struct {
		name    string
		mode    string
		targets []prober.TargetStatus
		want    int
	}{
		{"server mode is ready without targets", "server", nil, http.StatusOK},
		{"client with an empty registry is not ready", "client", nil, http.StatusServiceUnavailable},
		{"client still dialing is not ready", "client", dialStuck, http.StatusServiceUnavailable},
		{"client with one working socket is ready", "client", working, http.StatusOK},
		{"both mode with one working socket is ready", "both", working, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := prober.NewStatusRegistry()
			for _, s := range tc.targets {
				reg.Update(s)
			}
			rec := httptest.NewRecorder()
			readinessHandler(tc.mode, reg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rec.Code != tc.want {
				t.Errorf("/readyz in mode %s = %d, want %d (body %q)", tc.mode, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestStartMetricsServerTimeouts pins the HTTP timeouts: a multi-megabyte
// scrape over a slow link needs more than 10s to write, and a truncated
// response reads as the monitor itself being down. Reads stay short so a slow
// client still cannot hold a connection.

// TestStartMetricsServerTimeouts pins the HTTP timeouts: a multi-megabyte
// scrape over a slow link needs more than 10s to write, and a truncated
// response reads as the monitor itself being down. Reads stay short so a slow
// client still cannot hold a connection.
func TestStartMetricsServerTimeouts(t *testing.T) {
	p := &program{}
	srv, done, err := p.startMetricsServer("127.0.0.1:0", "", "", "", "", prober.NewStatusRegistry(), false, "client")
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result
		_ = srv.Close()
		<-done
	})
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s (10s truncates large scrapes)", srv.WriteTimeout)
	}
	if srv.ReadTimeout != 10*time.Second || srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadTimeout/ReadHeaderTimeout = %v/%v, want 10s/10s", srv.ReadTimeout, srv.ReadHeaderTimeout)
	}
}

// TestConcurrencyCapReturns503 pins both wirings of the scrape cap: /metrics
// applies it inside metricsHandlerFor, /status wraps limitConcurrent around
// the status handler. Excess requests get 503 and must never reach the inner
// handler; after the burst every slot must be reusable.
func TestConcurrencyCapReturns503(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		postBurst int
		handler   func(entered, release chan struct{}) http.Handler
	}{
		{
			name: "/metrics", path: "/metrics", postBurst: 1,
			handler: func(entered, release chan struct{}) http.Handler {
				return metricsHandlerFor(&blockingGatherer{entered: entered, release: release}, false)
			},
		},
		{
			name: "/status", path: "/status", postBurst: 10,
			handler: func(entered, release chan struct{}) http.Handler {
				return limitConcurrent(maxConcurrentScrapes, &blockingStatusHandler{entered: entered, release: release})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prober.InitMetrics()
			entered := make(chan struct{}, 8)
			release := make(chan struct{})
			h := tc.handler(entered, release)

			recs := make([]*httptest.ResponseRecorder, maxConcurrentScrapes)
			done := make([]chan struct{}, len(recs))
			for i := range recs {
				recs[i] = httptest.NewRecorder()
				done[i] = make(chan struct{})
				go func(i int) {
					defer close(done[i])
					h.ServeHTTP(recs[i], httptest.NewRequest(http.MethodGet, tc.path, nil))
				}(i)
			}
			for range maxConcurrentScrapes {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("requests never reached the inner handler (cap not applied?)")
				}
			}

			// The next request arrives while all slots are held: 503, and it
			// must never reach the inner handler. Served from a goroutine with
			// a bound so a regression that removes the cap fails fast instead
			// of hanging until the package timeout.
			third := make(chan int, 1)
			go func() {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
				third <- rec.Code
			}()
			select {
			case got := <-third:
				if got != http.StatusServiceUnavailable {
					t.Errorf("a request beyond the %d-slot cap must get 503, got %d", maxConcurrentScrapes, got)
				}
			case <-entered:
				t.Error("the concurrency cap is not applied: a further request reached the inner handler")
				close(release)
				<-third
				return
			case <-time.After(5 * time.Second):
				t.Fatal("the excess request neither returned nor reached the inner handler")
			}

			close(release)
			for i := range recs {
				select {
				case <-done[i]:
				case <-time.After(5 * time.Second):
					t.Fatalf("request %d did not finish after release", i)
				}
				if recs[i].Code != http.StatusOK {
					t.Errorf("in-flight request %d must complete with 200, got %d", i, recs[i].Code)
				}
			}

			// Slots must be reusable after the burst. /status runs ten
			// sequential requests because its release path must not leak a
			// slot across a run (including the panic path); /metrics only
			// needs one to prove the cap fell back to zero.
			for range tc.postBurst {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
				if rec.Code != http.StatusOK {
					t.Errorf("cap must release after the burst, got %d", rec.Code)
				}
			}
		})
	}
}

// TestStatusHandler_CapReleasesOnPanic pins that a panicking request still
// frees its semaphore slot: the cap wraps arbitrary handlers and a leaked
// slot would eventually 503 every /status request forever. The wrapper lets
// the panic propagate to net/http's server-side recovery, so the test
// mirrors that by recovering it itself. The inner handler panics exactly
// once, so the request after the panic also proves the freed slot serves.
func TestStatusHandler_CapReleasesOnPanic(t *testing.T) {
	var panicked bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !panicked {
			panicked = true
			panic("boom")
		}
		w.WriteHeader(http.StatusOK)
	})
	h := limitConcurrent(1, inner)
	func() {
		defer func() {
			if r := recover(); r != nil {
				return
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/status", nil))
	}()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("slot leaked after a panicking request: recovery request got %d, want 200", rec.Code)
	}
}

// TestREADME_FlagsTableAndBucketsMatchCode ties the user-facing documentation
// to the code. Both have drifted before: -echo-secret was registered but
// missing from the flags table, and the bucket list lost its 2.5s/3s edges.
// A hand-maintained copy in a test would drift too, so this reads README.md
// itself. The comparison is one-directional (registered ⊆ documented): the
// README may legitimately show example rows the binary does not register.

// TestStatusEndpointIsGatedLikeMetrics: /status exposes live link state and
// peer addresses, so it must carry the same Basic auth as /metrics; /healthz
// and /readyz stay open for orchestrators. Pins the wiring in
// startMetricsServer, not just the MetricsAuth handler in isolation.
func TestStatusEndpointIsGatedLikeMetrics(t *testing.T) {
	prober.InitMetrics()
	p := &program{}
	reg := prober.NewStatusRegistry()
	reg.Update(prober.TargetStatus{Name: "t", Address: "127.0.0.1:4000"})
	srv, done, err := p.startMetricsServer("127.0.0.1:0", "alice", "s3cret", "", "", reg, false, "client")
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result
		_ = srv.Close()
		<-done
	})
	if srv.Addr == "" {
		t.Fatal("startMetricsServer must publish the bound address for callers/tests")
	}
	get := func(path string, user, pass string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://"+srv.Addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get("/status", "", ""); got != http.StatusUnauthorized {
		t.Errorf("/status without credentials = %d, want 401 (it exposes peer addresses and link state)", got)
	}
	if got := get("/status", "alice", "s3cret"); got != http.StatusOK {
		t.Errorf("/status with credentials = %d, want 200", got)
	}
	if got := get("/healthz", "", ""); got != http.StatusOK {
		t.Errorf("/healthz must stay unauthenticated, got %d", got)
	}
	if got := get("/readyz", "", ""); got == http.StatusUnauthorized {
		t.Error("/readyz must stay unauthenticated (orchestrators cannot send credentials)")
	}
}

// TestRulesAndDashboardReferenceOnlyDefinedMetrics pins a coupling that has
// drifted before: a renamed metric silently turns a shipped alert or dashboard
// panel into "no data". Every link_* identifier in rules/link-monitor.yml and
// grafana-dashboard.json must be a metric defined in internal/prober/metrics.go
// (or one of the histogram suffixes the client library appends). promtool in CI
// would validate PromQL syntax, but not this, and the repo's suite needs nothing
// beyond go test.
// pi-lens-ignore: go-test-functions

// TestMetricsServerErrorLogReachesSlog pins two coupled facts: the metrics
// server has an ErrorLog at all, and net/http's own failures (TLS handshake
// errors, accept errors, recovered handler panics) reach slog instead of the
// std log package's os.Stderr — which is DISCARDED under the Windows service, so
// a handshake that fails on a fleet node left no trace anywhere. The producer is
// a real failing handshake (plaintext on the TLS port), not a synthetic logf
// call, so the wiring into net/http is what is exercised.
func TestMetricsServerErrorLogReachesSlog(t *testing.T) {
	prober.InitMetrics()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.crt"), filepath.Join(dir, "cert.key")
	writeTestCert(t, certPath, keyPath, "metrics-server", 1)
	logs := captureLogs(t)

	p := &program{}
	srv, done, err := p.startMetricsServer("127.0.0.1:0", "", "", certPath, keyPath, prober.NewStatusRegistry(), false, "server")
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result
		_ = srv.Close()
		<-done
	})
	if srv.ErrorLog == nil {
		t.Fatal("metricsSrv.ErrorLog is nil: net/http would write its failures to os.Stderr, which the SCM discards")
	}

	conn, err := net.Dial("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("dial %s: %v", srv.Addr, err)
	}
	// Plaintext bytes on a TLS port fail the handshake inside net/http, which
	// reports it through srv.ErrorLog.
	// pi-lens-ignore: go-ignored-call-result
	_, _ = conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: metrics\r\n\r\n"))
	// pi-lens-ignore: go-ignored-call-result
	_ = conn.Close()

	waitForLog(t, logs, "TLS handshake error")
}

// TestMetricsServerCertReloadWithoutRestart pins the hot reload: a renewed
// certificate pair must be served by the NEXT handshake, with no restart. A
// 90-day certificate on a service that is never restarted otherwise becomes a
// silent scrape blackout on expiry. The two certificates differ in CN length on
// purpose, so the (mtime, size) fingerprint the reloader keys on changes even on
// a filesystem with coarse timestamps.
func TestMetricsServerCertReloadWithoutRestart(t *testing.T) {
	prober.InitMetrics()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.crt"), filepath.Join(dir, "cert.key")
	writeTestCert(t, certPath, keyPath, "cert-one", 101)

	p := &program{}
	srv, done, err := p.startMetricsServer("127.0.0.1:0", "", "", certPath, keyPath, prober.NewStatusRegistry(), false, "server")
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result
		_ = srv.Close()
		<-done
	})
	if got := servedCert(t, srv.Addr); got.SerialNumber.Int64() != 101 || got.Subject.CommonName != "cert-one" {
		t.Fatalf("startup certificate = serial %d cn %q, want 101/cert-one", got.SerialNumber.Int64(), got.Subject.CommonName)
	}

	writeTestCert(t, certPath, keyPath, "cert-two-renewed-longer", 202)

	got := servedCert(t, srv.Addr)
	if got.SerialNumber.Int64() != 202 || got.Subject.CommonName != "cert-two-renewed-longer" {
		t.Errorf("after renewal the handshake served serial %d cn %q, want 202/cert-two-renewed-longer (no restart, no reload)",
			got.SerialNumber.Int64(), got.Subject.CommonName)
	}
}

// TestMetricsServerCertReloadFailureKeepsPrevious pins the degraded path: an
// unreadable or half-written replacement must NOT break scraping. The previously
// loaded certificate keeps being served, the failure is reported exactly once
// for that file pair — a Warn per handshake would flood the log the reload
// exists to make visible, and failing the handshake would black out /metrics for
// the duration of a transient write — AND the pair is retried after
// certReloadRetryCooldown. The retry is what makes an in-place repair
// observable: the repair below restores the finished bytes under the broken
// pair's own mtime and size, so the (mtime, size) fingerprint never changes and
// a pure "already tried" memo would serve the expired certificate forever.
func TestMetricsServerCertReloadFailureKeepsPrevious(t *testing.T) {
	origCooldown := certReloadRetryCooldown
	certReloadRetryCooldown = time.Second
	t.Cleanup(func() { certReloadRetryCooldown = origCooldown })

	prober.InitMetrics()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.crt"), filepath.Join(dir, "cert.key")
	writeTestCert(t, certPath, keyPath, "cert-one", 101)
	logs := captureLogs(t)

	// The renewal is generated up front so the broken replacement written
	// later can carry exactly its byte counts: the repair writes these bytes
	// back under the broken pair's mtime, leaving the fingerprint untouched.
	renewedCertPath, renewedKeyPath := filepath.Join(dir, "renewed.crt"), filepath.Join(dir, "renewed.key")
	writeTestCert(t, renewedCertPath, renewedKeyPath, "cert-two-renewed-longer", 202)
	renewedCert, err := os.ReadFile(renewedCertPath)
	if err != nil {
		t.Fatalf("read renewed certificate: %v", err)
	}
	renewedKey, err := os.ReadFile(renewedKeyPath)
	if err != nil {
		t.Fatalf("read renewed key: %v", err)
	}

	p := &program{}
	srv, done, err := p.startMetricsServer("127.0.0.1:0", "", "", certPath, keyPath, prober.NewStatusRegistry(), false, "server")
	if err != nil {
		t.Fatalf("startMetricsServer: %v", err)
	}
	t.Cleanup(func() {
		// pi-lens-ignore: go-ignored-call-result
		_ = srv.Close()
		<-done
	})

	// A half-written renewal: no PEM data at all, but the same sizes as the
	// finished pair. The (mtime, size) it lands on is the fingerprint the
	// failed load is recorded under.
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.WriteFile(certPath, []byte(strings.Repeat("x", len(renewedCert))), 0o600); err != nil {
		t.Fatalf("replace certificate with garbage: %v", err)
	}
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("x", len(renewedKey))), 0o600); err != nil {
		t.Fatalf("replace key with garbage: %v", err)
	}
	brokenCertInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat broken certificate: %v", err)
	}
	brokenKeyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat broken key: %v", err)
	}
	if got := servedCert(t, srv.Addr); got.SerialNumber.Int64() != 101 {
		t.Fatalf("a failed reload must keep serving the previous certificate, got serial %d", got.SerialNumber.Int64())
	}

	// Repair in place without touching (mtime, size): put the finished bytes
	// back and restore the timestamps the broken pair was recorded under.
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.WriteFile(certPath, renewedCert, 0o600); err != nil {
		t.Fatalf("restore certificate: %v", err)
	}
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.WriteFile(keyPath, renewedKey, 0o600); err != nil {
		t.Fatalf("restore key: %v", err)
	}
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.Chtimes(certPath, brokenCertInfo.ModTime(), brokenCertInfo.ModTime()); err != nil {
		t.Fatalf("restore certificate mtime: %v", err)
	}
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.Chtimes(keyPath, brokenKeyInfo.ModTime(), brokenKeyInfo.ModTime()); err != nil {
		t.Fatalf("restore key mtime: %v", err)
	}
	if repaired, err := os.Stat(certPath); err != nil {
		t.Fatalf("stat repaired certificate: %v", err)
	} else if repaired.Size() != brokenCertInfo.Size() || !repaired.ModTime().Equal(brokenCertInfo.ModTime()) {
		t.Fatalf("the in-place repair changed the fingerprint (size %d->%d, mtime %v->%v): it no longer exercises the cooldown retry",
			brokenCertInfo.Size(), repaired.Size(), brokenCertInfo.ModTime(), repaired.ModTime())
	}

	// Still inside the cooldown: the repaired pair must not be re-read yet, so
	// a broken renewal does not cost a file read (and a Warn) per handshake.
	if got := servedCert(t, srv.Addr); got.SerialNumber.Int64() != 101 {
		t.Errorf("within the retry cooldown the handshake served serial %d, want the cached 101", got.SerialNumber.Int64())
	}
	if n := countLogs(logs, "keeping the previously loaded certificate", 300*time.Millisecond); n != 1 {
		t.Errorf("a failed reload logged %d times for one file pair, want exactly 1", n)
	}

	// Past the cooldown the unchanged fingerprint is retried, so the repaired
	// pair takes effect with no restart and no (mtime, size) change.
	// pi-lens-ignore: go-time-sleep-test
	time.Sleep(certReloadRetryCooldown)
	got := servedCert(t, srv.Addr)
	if got.SerialNumber.Int64() != 202 || got.Subject.CommonName != "cert-two-renewed-longer" {
		t.Errorf("after the retry cooldown the handshake served serial %d cn %q, want 202/cert-two-renewed-longer",
			got.SerialNumber.Int64(), got.Subject.CommonName)
	}
	if n := countLogs(logs, "reloaded", 300*time.Millisecond); n != 1 {
		t.Errorf("the repaired pair was reloaded %d times, want exactly 1", n)
	}
}

// TestWarnUnauthenticatedMetricsBind pins the exposure warning: the listener
// defaults to localhost, so widening -metrics without credentials is otherwise a
// silent decision to publish the probe topology, peer IPs and per-link RTT/loss
// to every host that can reach the port.
func TestWarnUnauthenticatedMetricsBind(t *testing.T) {
	for _, tc := range []struct {
		name, addr, user string
		wantWarn         bool
	}{
		{"loopback without auth", "127.0.0.1:2112", "", false},
		{"loopback v6 without auth", "[::1]:2112", "", false},
		{"wildcard v4 without auth", "0.0.0.0:2112", "", true},
		{"wildcard v6 without auth", "[::]:2112", "", true},
		{"routable without auth", "192.0.2.5:2112", "", true},
		{"wildcard with auth", "0.0.0.0:2112", "alice", false},
		{"routable with auth", "192.0.2.5:2112", "alice", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tcpAddr, err := net.ResolveTCPAddr("tcp", tc.addr)
			if err != nil {
				t.Fatalf("resolve %q: %v", tc.addr, err)
			}
			buf := captureWarns(t)
			warnUnauthenticatedMetricsBind(tcpAddr, tc.user)
			got := strings.Contains(buf.String(), "WITHOUT authentication")
			if got != tc.wantWarn {
				t.Errorf("warnUnauthenticatedMetricsBind(%s, user=%q) warned = %v, want %v (log: %s)",
					tc.addr, tc.user, got, tc.wantWarn, buf.String())
			}
		})
	}
}

// writeTestCert generates a self-signed server certificate for cn and writes the
// pair to certPath/keyPath. Certificates are generated rather than checked in:
// the reloader keys on (mtime, size), so the test has to control exactly when
// the bytes on disk are replaced.
func writeTestCert(t *testing.T, certPath, keyPath, cn string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	// pi-lens-ignore: go-path-traversal (t.TempDir)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// servedCert dials addr and returns the certificate the server presented. No
// ServerName is set (the client dials an IP literal), which is the scrape shape
// crypto/tls serves only through GetCertificate.
func servedCert(t *testing.T, addr string) *x509.Certificate {
	t.Helper()
	// pi-lens-ignore: go-insecure-skip-verify (self-signed test certificate)
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial %s: %v", addr, err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatalf("no peer certificate from %s", addr)
	}
	return certs[0]
}

// captureLogs installs a channel-backed slog handler for the test and returns
// the channel. A bytes.Buffer would be written by the serve/handshake goroutines
// while the test reads it, which is a data race — and the traffic here is
// produced by another goroutine by construction.
func captureLogs(t *testing.T) <-chan string {
	t.Helper()
	prev := slog.Default()
	ch := make(chan string, 128)
	slog.SetDefault(slog.New(chanHandler{ch: ch}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return ch
}

// waitForLog drains ch until a record whose message contains want arrives.
func waitForLog(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case msg := <-ch:
			if strings.Contains(msg, want) {
				return
			}
		case <-deadline:
			t.Fatalf("no log record containing %q within 5s", want)
		}
	}
}

// countLogs counts records whose message contains want, draining ch for window.
// The caller has already provoked them; the window only bounds the wait.
func countLogs(ch <-chan string, want string, window time.Duration) int {
	deadline := time.After(window)
	n := 0
	for {
		select {
		case msg := <-ch:
			if strings.Contains(msg, want) {
				n++
			}
		case <-deadline:
			return n
		}
	}
}
