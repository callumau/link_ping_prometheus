//go:build linux

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2ELinuxPullConfigSH(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock not installed")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		if _, err := exec.LookPath("jq"); err != nil {
			t.Skip("neither python3 nor jq installed")
		}
	}

	script, err := filepath.Abs("../../deploy/mesh/pull-config.sh")
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	bare := filepath.Join(tmp, "bare.git")
	seed := filepath.Join(tmp, "seed")
	dest := filepath.Join(tmp, "dest")
	work := filepath.Join(tmp, "work with spaces", "checkout")
	key := filepath.Join(tmp, "deploy_key")
	knownHosts := filepath.Join(tmp, "known_hosts")
	hookMarker := filepath.Join(tmp, "hook-ran")

	if err := os.WriteFile(key, []byte("dummy-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("example.invalid ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
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

	targetsV1 := `[{"name":"site-a","address":"192.0.2.10:4000"}]`
	if err := os.WriteFile(filepath.Join(seed, "targets.json"), []byte(targetsV1), 0o644); err != nil {
		t.Fatal(err)
	}
	// Commit a malicious .no-hooks/post-checkout inside the repo to prove
	// pull-config.sh no longer points core.hooksPath inside $work.
	hooksDir := filepath.Join(seed, ".no-hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hookScript := fmt.Sprintf("#!/bin/sh\ntouch %q\n", hookMarker)
	if err := os.WriteFile(filepath.Join(hooksDir, "post-checkout"), []byte(hookScript), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(seed, "add", "targets.json", ".no-hooks/post-checkout")
	runGit(seed, "commit", "-m", "initial")
	runGit(seed, "push", "-u", "origin", "main")

	runPull := func(workDir string, extraEnv ...string) (string, error) {
		cmd := exec.Command("sh", script, bare, "main", dest, key, knownHosts)
		cmd.Env = append(os.Environ(), append([]string{
			"LINK_PING_CONFIG_WORK=" + workDir,
		}, extraEnv...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 1. Fresh clone into a path with spaces: succeeds, installs 0644, never
	//    executes .no-hooks/post-checkout, and places lock outside /run/lock.
	if out, err := runPull(work); err != nil {
		t.Fatalf("initial pull failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(hookMarker); err == nil {
		t.Fatal("malicious .no-hooks/post-checkout executed during clone")
	}
	livePath := filepath.Join(dest, "targets.json")
	got, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatalf("read installed targets.json: %v", err)
	}
	if string(got) != targetsV1 {
		t.Fatalf("installed targets.json = %q, want %q", got, targetsV1)
	}
	fi, err := os.Stat(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("installed targets.json mode = %04o, want 0644", fi.Mode().Perm())
	}
	defaultLock := filepath.Join(filepath.Dir(work), ".link_ping_pull_config.lock")
	lfi, err := os.Stat(defaultLock)
	if err != nil {
		t.Fatalf("expected private lock at %s: %v", defaultLock, err)
	}
	if lfi.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %04o, want 0600", lfi.Mode().Perm())
	}

	// 2. Broken JSON pushed to repo must fail fresh clone and keep live targets.json.
	if err := os.WriteFile(filepath.Join(seed, "targets.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(seed, "add", "targets.json")
	runGit(seed, "commit", "-m", "broken json")
	runGit(seed, "push", "origin", "main")

	work2 := filepath.Join(tmp, "work-broken")
	if out, err := runPull(work2); err == nil {
		t.Fatalf("expected broken JSON pull to fail, got success:\n%s", out)
	}
	afterBroken, err := os.ReadFile(livePath)
	if err != nil || string(afterBroken) != targetsV1 {
		t.Fatalf("live targets.json mutated on failed pull: got %q (err=%v)", afterBroken, err)
	}

	// 3. Group-readable deploy key must be refused before cloning.
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	work3 := filepath.Join(tmp, "work-badkey")
	if out, err := runPull(work3); err == nil {
		t.Fatalf("expected 0640 key to be refused, got success:\n%s", out)
	} else if !strings.Contains(out, "group/world-accessible") {
		t.Fatalf("unexpected error for bad key mode: %s", out)
	}
}
