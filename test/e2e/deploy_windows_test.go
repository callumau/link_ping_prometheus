//go:build windows

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

func runWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func TestE2EWindowsTakeownAndReparseGuard(t *testing.T) {
	if !svcHasAdmin(t) {
		t.Skip("takeown /a requires Administrator privileges")
	}
	tmp := t.TempDir()

	// Single-directory form used for ProgramData container and logs dir.
	singleDir := filepath.Join(tmp, "single")
	psSingle := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$d = '%s'
if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
$it = Get-Item -LiteralPath $d -Force
if ($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'unexpected reparse' }
takeown.exe /f "$d" /a | Out-Null
if ($LASTEXITCODE -ne 0) { throw "takeown failed on $d ($LASTEXITCODE)" }
icacls.exe "$d" /inheritance:r /grant "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed on $d ($LASTEXITCODE)" }
`, singleDir)
	if out, err := runWithTimeout(60*time.Second, "powershell.exe", "-NoProfile", "-Command", psSingle); err != nil {
		t.Fatalf("single-dir takeown/icacls failed: %v\n%s", err, out)
	}

	// Recursive form used for pull_config and config-repo work dirs.
	recDir := filepath.Join(tmp, "recursive")
	if err := os.MkdirAll(filepath.Join(recDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, "sub", "file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	psRec := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$d = '%s'
$it = Get-Item -LiteralPath $d -Force
if ($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'reparse' }
$bad = @(Get-ChildItem -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
if ($bad.Count -gt 0) { throw 'child reparse' }
takeown.exe /f "$d" /a /r /d Y | Out-Null
if ($LASTEXITCODE -ne 0) { throw "takeown /r failed on $d ($LASTEXITCODE)" }
$grant = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
icacls.exe "$d" /inheritance:r /grant $grant /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls /T failed on $d ($LASTEXITCODE)" }
`, recDir)
	if out, err := runWithTimeout(60*time.Second, "powershell.exe", "-NoProfile", "-Command", psRec); err != nil {
		t.Fatalf("recursive takeown/icacls failed: %v\n%s", err, out)
	}

	// NTFS junction must be detected and rejected before takeown/icacls runs.
	juncTarget := filepath.Join(tmp, "target")
	juncLink := filepath.Join(tmp, "junc")
	if err := os.MkdirAll(juncTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := runWithTimeout(60*time.Second, "cmd.exe", "/c", "mklink", "/J", juncLink, juncTarget); err != nil {
		t.Fatalf("mklink /J failed: %v\n%s", err, out)
	}
	psJunc := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$d = '%s'
$it = Get-Item -LiteralPath $d -Force
if ($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'reparse-refused' }
`, juncLink)
	if out, err := runWithTimeout(60*time.Second, "powershell.exe", "-NoProfile", "-Command", psJunc); err == nil {
		t.Fatalf("expected junction to be refused, got success:\n%s", out)
	} else if !strings.Contains(string(out), "reparse-refused") {
		t.Fatalf("unexpected error for junction: %v\n%s", err, out)
	}
}

func TestE2EWindowsPullConfigPS1(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	script, err := filepath.Abs("../../deploy/mesh/pull-config.ps1")
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	bare := filepath.Join(tmp, "bare.git")
	seed := filepath.Join(tmp, "seed")
	dest := filepath.Join(tmp, "dest")
	work := filepath.Join(tmp, "work-1")
	key := filepath.Join(tmp, "deploy_key")
	knownHosts := filepath.Join(tmp, "known_hosts")
	hookMarker := filepath.Join(tmp, "hook-ran")

	if err := os.WriteFile(key, []byte("dummy-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runWithTimeout(60*time.Second, "icacls.exe", key, "/inheritance:r", "/grant", "*S-1-5-18:F", "*S-1-5-32-544:F"); err != nil {
		t.Fatalf("restrict key ACL: %v\n%s", err, out)
	}
	if err := os.WriteFile(knownHosts, []byte("example.invalid ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runGit := func(dir string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...)
		if dir != "" {
			cmd.Dir = dir
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("", "init", "--bare", bare)
	runGit(bare, "symbolic-ref", "HEAD", "refs/heads/main")
	runGit("", "clone", bare, seed)
	runGit(seed, "checkout", "-b", "main")
	runGit(seed, "config", "user.name", "ci")
	runGit(seed, "config", "user.email", "ci@example.invalid")

	// Single-element JSON array: Windows PowerShell 5.1 ConvertFrom-Json
	// unrolls 1-element arrays into a scalar unless handled carefully.
	oneTarget := `[{"name":"site-a","address":"192.0.2.10:4000"}]`
	if err := os.WriteFile(filepath.Join(seed, "targets.json"), []byte(oneTarget), 0o644); err != nil {
		t.Fatal(err)
	}
	hooksDir := filepath.Join(seed, ".no-hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "post-checkout"), []byte("#!/bin/sh\ntouch "+filepath.ToSlash(hookMarker)+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(seed, "add", "targets.json", ".no-hooks/post-checkout")
	runGit(seed, "commit", "-m", "one target")
	runGit(seed, "push", "-u", "origin", "main")

	runPS1 := func(workDir string) (string, error) {
		out, err := runWithTimeout(60*time.Second, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script,
			"-Repo", bare, "-Branch", "main", "-Work", workDir, "-Dest", dest, "-Key", key, "-KnownHosts", knownHosts)
		return string(out), err
	}

	if out, err := runPS1(work); err != nil {
		t.Fatalf("pull-config.ps1 1-target pull failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(hookMarker); err == nil {
		t.Fatal("malicious .no-hooks/post-checkout executed on Windows clone")
	}
	live := filepath.Join(dest, "targets.json")
	got, err := os.ReadFile(live)
	if err != nil || string(got) != oneTarget {
		t.Fatalf("installed targets.json = %q (err=%v), want %q", got, err, oneTarget)
	}

	// Truncating live targets.json to 0 bytes must not crash Compare-Object.
	if err := os.WriteFile(live, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runPS1(filepath.Join(tmp, "work-empty-live")); err != nil {
		t.Fatalf("pull-config.ps1 over 0-byte live file failed: %v\n%s", err, out)
	}
	if got2, err := os.ReadFile(live); err != nil || string(got2) != oneTarget {
		t.Fatalf("targets.json after 0-byte overwrite = %q (err=%v)", got2, err)
	}

	// Non-array JSON object ({}) must be refused while keeping previous live file.
	if err := os.WriteFile(filepath.Join(seed, "targets.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(seed, "add", "targets.json")
	runGit(seed, "commit", "-m", "non-array")
	runGit(seed, "push", "origin", "main")
	if out, err := runPS1(filepath.Join(tmp, "work-obj")); err == nil {
		t.Fatalf("expected non-array JSON to fail, got success:\n%s", out)
	}
	if got3, err := os.ReadFile(live); err != nil || string(got3) != oneTarget {
		t.Fatalf("live targets.json changed after rejected object JSON: %q", got3)
	}

	// Broad Users read ACE on deploy key must fail closed.
	if out, err := runWithTimeout(60*time.Second, "icacls.exe", key, "/grant", "*S-1-5-32-545:R"); err != nil {
		t.Fatalf("grant Users read on key: %v\n%s", err, out)
	}
	if out, err := runPS1(filepath.Join(tmp, "work-wide-key")); err == nil {
		t.Fatalf("expected wide key ACL to be refused, got success:\n%s", out)
	}
}

func TestE2EWindowsBatchInstallerGuards(t *testing.T) {
	if os.Getenv("LPP_E2E_WINDOWS") != "1" {
		t.Skip("set LPP_E2E_WINDOWS=1 to run elevated Windows batch installer guards")
	}
	if !svcHasAdmin(t) {
		t.Skip("SCM requires elevation")
	}

	installBat, err := filepath.Abs("../../installer/windows/install-service.bat")
	if err != nil {
		t.Fatal(err)
	}
	uninstallBat, err := filepath.Abs("../../installer/windows/uninstall-service.bat")
	if err != nil {
		t.Fatal(err)
	}

	// Ensure clean baseline before testing install-service.bat.
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	if s, oerr := m.OpenService("link_ping_prometheus"); oerr == nil {
		_ = s.Close()
		t.Skip("service link_ping_prometheus already installed before batch guard test")
	}

	tmp := t.TempDir()
	// 1. Verify uninstall-service.bat does not fall through :done into :RefuseReparse
	//    when passed a junction path as %1.
	juncTarget := filepath.Join(tmp, "jtarget")
	juncLink := filepath.Join(tmp, "jlink")
	if err := os.MkdirAll(juncTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := runWithTimeout(60*time.Second, "cmd.exe", "/c", "mklink", "/J", juncLink, juncTarget); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}
	uctx, ucancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer ucancel()
	ucmd := exec.CommandContext(uctx, "cmd.exe", "/c", uninstallBat, juncLink)
	ucmd.Stdin = strings.NewReader("n\r\n")
	if out, err := ucmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstall-service.bat fell through into RefuseReparse or failed: %v\n%s", err, out)
	} else if strings.Contains(string(out), "is a reparse point") {
		t.Fatalf("uninstall-service.bat fell through :done into :RefuseReparse:\n%s", out)
	}

	// 2. Verify install-service.bat refuses Basic auth without TLS BEFORE
	//    installing anything in SCM (no orphaned service left behind).
	stage := filepath.Join(tmp, "stage")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	exeBytes, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "link_ping_prometheus.exe"), exeBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	batBytes, err := os.ReadFile(installBat)
	if err != nil {
		t.Fatal(err)
	}
	stageBat := filepath.Join(stage, "install-service.bat")
	if err := os.WriteFile(stageBat, batBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = runWithTimeout(30*time.Second, binPath, "-svc=uninstall")
	})

	ictx, icancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer icancel()
	icmd := exec.CommandContext(ictx, "cmd.exe", "/c", stageBat)
	icmd.Stdin = strings.NewReader(strings.Join([]string{
		"server",
		"127.0.0.1:2112",
		"127.0.0.1",
		filepath.Join(tmp, "logs"),
		"",
		"",
		"n",
		"prom",
		"prompass",
		"",
		"",
	}, "\r\n") + "\r\n")
	if out, err := icmd.CombinedOutput(); err == nil {
		t.Fatalf("expected install-service.bat to refuse Basic auth without TLS, got exit 0:\n%s", out)
	} else if !strings.Contains(string(out), "neither -metrics-tls-cert/-metrics-tls-key nor -metrics-allow-insecure") {
		t.Fatalf("unexpected install-service.bat output:\n%s", out)
	}
	if s, oerr := m.OpenService("link_ping_prometheus"); oerr == nil {
		_ = s.Close()
		t.Fatal("install-service.bat left an orphaned service in SCM after refusing Basic auth without TLS")
	}

	// 3. Verify install-service.bat refuses a junction at LOG_DIR and exits non-zero.
	jctx, jcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer jcancel()
	jcmd := exec.CommandContext(jctx, "cmd.exe", "/c", stageBat)
	jcmd.Stdin = strings.NewReader(strings.Join([]string{
		"server",
		"127.0.0.1:2112",
		"127.0.0.1",
		juncLink,
		"",
		"",
		"n",
		"",
		"",
		"",
		"",
		"y",
	}, "\r\n") + "\r\n")
	out, err := jcmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected install-service.bat to refuse junction LOG_DIR, got exit 0:\n%s", out)
	}
	if !strings.Contains(string(out), "is a reparse point") {
		t.Fatalf("expected reparse-point refusal for junction LOG_DIR, got:\n%s", out)
	}
	// Clean up %ProgramFiles%\link_ping_prometheus copied before LOG_DIR check.
	cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cleanCancel()
	uclean := exec.CommandContext(cleanCtx, "cmd.exe", "/c", uninstallBat)
	uclean.Stdin = strings.NewReader("n\r\n")
	_ = uclean.Run()
}
