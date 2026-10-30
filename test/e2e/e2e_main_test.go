package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Black-box e2e suite: every test here drives the COMPILED binary only —
// no internal/prober imports, no exported-package reach-ins. The suite
// covers the modes/endpoints/probe functions that ship (server, client,
// both, secret pairing, payload integrity, MTU sweep, targets hot reload,
// /status shape) and the service lifecycle with the executable
// (-svc=install/start/stop/uninstall on Windows; systemd unit lifecycle on
// Linux; the -svc=install refusal on Linux/darwin enforcing the
// supply-chain decision). Console tests run everywhere; the privileged
// service tests self-skip when the environment cannot grant them.

var (
	binPath string
)

// TestMain builds the release binary once for the whole suite so the
// tests exercise the exact artifact a user runs.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lpp-e2e-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e tmpdir:", err)
		os.Exit(1)
	}
	out := filepath.Join(dir, "link_ping_prometheus")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	build := exec.Command("go", "build", "-o", out, "../../.")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e build failed:", err)
		os.Exit(1)
	}
	binPath = out
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// binProc is one running binary instance with its combined output
// captured to a buffer.
type binProc struct {
	cmd    *exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
	buf    *syncBuffer
}

// waitMetricGTE polls the /metrics exposition until the named series
// reaches a value >= min (positive-condition polling; series exist at 0
// from first scrape so a substring wait is never enough).
func waitMetricGTE(t *testing.T, url, name string, min float64, timeout time.Duration) float64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var v float64
	for time.Now().Before(deadline) {
		_, body := httpGetIf(t, url)
		if v = metricValue(body, name); v >= min {
			return v
		}
		// e2e poll
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("metric %s never reached >= %v within %v (last=%v)", name, min, timeout, v)
	return 0
}

// startBin launches the binary with args. Output is race-buffered; read
// proc.buf.String() in asserts. Cleanup kills the process (SIGTERM on unix via
// cancel-friendly process kill; Windows uses Process.Kill, which is
// what a service-control test leaves behind anyway).
func startBin(t *testing.T, args ...string) *binProc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	buf := &syncBuffer{}
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Stdout = buf
	cmd.Stderr = buf
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start %v: %v", args, err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	return &binProc{cmd: cmd, ctx: ctx, cancel: cancel, buf: buf}
}

// syncBuffer is an io.Writer safe for the exec pipes' concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freePort reserves an OS port without holding it (close-on-check race is
// tolerated: self-referencing e2e services are the only listeners).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	// pi-lens-ignore: go-ignored-call-result
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// httpGetIf performs one GET; returns status + body.
func httpGetIf(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, ""
	}
	// pi-lens-ignore: go-ignored-call-result
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, ""
	}
	return resp.StatusCode, string(body)
}

// waitHTTP polls until the endpoint returns 200 and the body contains
// want (or empty want: just 200).
func waitHTTP(t *testing.T, url, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastBody string
	for time.Now().Before(deadline) {
		code, body := httpGetIf(t, url)
		if code == 200 && (want == "" || strings.Contains(body, want)) {
			return body
		}
		lastBody = body
		// e2e poll loop: unavoidable sleep between probes
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("http %s never satisfied (want %q) within %v; last body: %.400s", url, want, timeout, lastBody)
	return ""
}

// metricValue extracts a value from /metrics text: matches the first
// line "name{labels} value" or bare "name value". 0 when absent.
func metricValue(body, line string) float64 {
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, line+" ") || strings.HasPrefix(l, line+"{") {
			fields := strings.Fields(l)
			if len(fields) > 0 {
				var v float64
				fmt.Sscanf(fields[len(fields)-1], "%f", &v)
				return v
			}
		}
	}
	return 0
}

// writeTargetsFile writes a targets JSON file with names/addresses.
func writeTargetsFile(t *testing.T, dir string, targets map[string]string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("[")
	first := true
	for n, a := range targets {
		if !first {
			b.WriteString(",")
		}
		first = false
		b.WriteString(fmt.Sprintf(`{"name":%q,"address":%q}`, n, a))
	}
	b.WriteString("]")
	p := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write targets: %v", err)
	}
	return p
}
