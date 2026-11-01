package main

import (
	"os"
	"strings"
	"testing"
)

// These tests pin deployment-script invariants that no Go code can express and
// that the audit found broken. They are deliberately textual: the shipped
// Ansible plays and Windows batch scripts are not executed by CI (no SCM, no
// registry, no PowerShell on the Linux runner), and the regressions they guard
// are orderings and template expressions, not behaviour a unit test could
// otherwise reach.

func readDeploymentFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func mustContain(t *testing.T, path, body, needle, why string) {
	t.Helper()
	if !strings.Contains(body, needle) {
		t.Errorf("%s: missing %q (%s)", path, needle, why)
	}
}

func mustNotContain(t *testing.T, path, body, needle, why string) {
	t.Helper()
	if strings.Contains(body, needle) {
		t.Errorf("%s: found forbidden %q (%s)", path, needle, why)
	}
}

func indexOf(t *testing.T, path, body, needle string) int {
	t.Helper()
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatalf("%s: missing %q", path, needle)
	}
	return i
}

// TestWindowsInstallerOrdersACLBeforeSecrets pins the credential-window fix:
// the per-service Environment key inherits BUILTIN\Users read from ...\Services,
// so writing the plaintext password and HMAC secret before restricting the key
// exposes them to every local user for the length of the reg.exe calls plus
// PowerShell startup.
func TestWindowsInstallerOrdersACLBeforeSecrets(t *testing.T) {
	path := "installer/windows/install-service.bat"
	body := readDeploymentFile(t, path)

	acl := indexOf(t, path, body, "Restrict the key BEFORE writing any value")
	firstSecret := indexOf(t, path, body, "/v LINK_PING_METRICS_PASS")
	if acl > firstSecret {
		t.Errorf("%s: the Environment key must be ACL'd before any credential is written (ACL block at %d, first secret at %d)", path, acl, firstSecret)
	}
	mustContain(t, path, body, "if (-not (Test-Path $k)) { New-Item -Path $k -Force", "the key must be created restricted before the writes")
}

// TestWindowsInstallerOwnsProgramDataContainer pins the ownership fix. A
// standard user can create C:\ProgramData\link_ping_prometheus and keeps
// implicit WRITE_DAC, so creating the directory is not enough: the installer
// must take ownership before restricting the DACL.
func TestWindowsInstallerOwnsProgramDataContainer(t *testing.T) {
	path := "installer/windows/install-service.bat"
	body := readDeploymentFile(t, path)

	mustContain(t, path, body, ":HardenDataDir", "the container hardening subroutine")
	mustContain(t, path, body, "call :HardenDataDir", "the container hardening must be invoked")
	takeown := indexOf(t, path, body, "takeown /f \"%DATA_DIR%\" /a")
	icacls := indexOf(t, path, body, "icacls \"%DATA_DIR%\" /inheritance:r")
	if takeown > icacls {
		t.Errorf("%s: takeown must precede icacls on the container (takeown %d, icacls %d)", path, takeown, icacls)
	}
}

// TestWindowsUninstallerDoesNotWeakenLogACL pins the uninstall fix: resetting
// the DACL before a best-effort delete leaves the directory readable by every
// local user whenever the delete fails, and the delete never needed the reset
// (Administrators already hold full control).
func TestWindowsUninstallerDoesNotWeakenLogACL(t *testing.T) {
	path := "installer/windows/uninstall-service.bat"
	body := readDeploymentFile(t, path)

	mustNotContain(t, path, body, `icacls "%LOG_DIR%" /reset`, "the reset only weakens the DACL")
	mustNotContain(t, path, body, `icacls "%SVC_LOG_DIR%" /reset`, "the reset only weakens the DACL")
	mustContain(t, path, body, "call :discover_custom", "custom log discovery must run before the service key disappears")
	discover := indexOf(t, path, body, "call :discover_custom")
	uninstall := indexOf(t, path, body, `"%INSTALLED_EXE%" -svc=uninstall`)
	if discover > uninstall {
		t.Errorf("%s: custom log discovery must precede the service deletion (discover %d, uninstall %d)", path, discover, uninstall)
	}
}

// TestAnsibleRetiresClearedCredentials pins the rotation fix. A cleared vault
// variable must delete its registry value; the previous `when: item.data |
// length > 0` skipped the task, so the retired HMAC secret stayed installed and
// kept authenticating probes as -echo-secret-old.
func TestAnsibleRetiresClearedCredentials(t *testing.T) {
	for _, path := range []string{"deploy/ansible/playbook.yml", "deploy/ansible/mesh.yml"} {
		body := readDeploymentFile(t, path)
		mustContain(t, path, body, `state: "{{ 'present' if item.data | length > 0 else 'absent' }}"`,
			"credential state must be derived from the value")
		if strings.Contains(body, "\n      when: item.data | length > 0") {
			t.Errorf("%s: the per-item `when` gate makes the absent branch unreachable", path)
		}
	}
}

// TestAnsibleOwnedFlagGuardRejectsGNUFlags pins the guard bypass: Go accepts
// --name=value, so a one-dash regex let --metrics/--allow/--mode override the
// templated flags after the guardrails had approved the variables.
func TestAnsibleOwnedFlagGuardRejectsGNUFlags(t *testing.T) {
	for _, path := range []string{"deploy/ansible/playbook.yml", "deploy/ansible/mesh.yml"} {
		body := readDeploymentFile(t, path)
		mustContain(t, path, body, `select('match', '^--?(metrics|mode|allow`, "both -flag and --flag must be rejected")
		if strings.Contains(body, `select('match', '^-(metrics|mode|allow`) {
			t.Errorf("%s: a one-dash-only owned-flag regex lets --flag tokens through", path)
		}
	}
}

// TestAnsibleMetricsGuardrailDoesNotAcceptTLSForAuth pins the exposure fix: TLS
// authenticates the server, not the scraper, so a wildcard listener with no
// credentials must be refused even when a certificate is configured.
func TestAnsibleMetricsGuardrailDoesNotAcceptTLSForAuth(t *testing.T) {
	for _, path := range []string{"deploy/ansible/playbook.yml", "deploy/ansible/mesh.yml"} {
		body := readDeploymentFile(t, path)
		mustNotContain(t, path, body, "and not (link_ping_metrics_tls | bool)",
			"TLS must not substitute for Basic auth in the exposure guardrail")
	}
}

// TestAnsibleOwnsTheWindowsServiceDirectories pins that every directory a
// SYSTEM service or scheduled task writes to or executes from is re-owned
// before use, in both Windows plays.
func TestAnsibleOwnsTheWindowsServiceDirectories(t *testing.T) {
	pb := readDeploymentFile(t, "deploy/ansible/playbook.yml")
	mustContain(t, "deploy/ansible/playbook.yml", pb, "takeown.exe /f \"$d\" /a", "the container must be re-owned")
	mustContain(t, "deploy/ansible/playbook.yml", pb, "link_ping_win_data_dir", "the container needs its own variable")

	m := readDeploymentFile(t, "deploy/ansible/mesh.yml")
	mustContain(t, "deploy/ansible/mesh.yml", m, "link_ping_win_pull_work", "the pull work directory must be created")
	if strings.Count(m, "takeown.exe /f \"$d\" /a") < 3 {
		t.Errorf("deploy/ansible/mesh.yml: container, pull directory and pull work directory must all be re-owned")
	}
}

// TestPullScriptsNeutraliseRepoLocalGitConfig pins the code-execution fix:
// repository-local core.fsmonitor/core.hooksPath run in fetch/reset, and the
// SYSTEM/scheduled pull must not let a checkout configuration choose a program.
func TestPullScriptsNeutraliseRepoLocalGitConfig(t *testing.T) {
	sh := readDeploymentFile(t, "deploy/mesh/pull-config.sh")
	mustContain(t, "deploy/mesh/pull-config.sh", sh, "core.fsmonitor=false", "fsmonitor executes on fetch")
	mustContain(t, "deploy/mesh/pull-config.sh", sh, "core.hooksPath=", "hooks execute on fetch/reset")

	ps := readDeploymentFile(t, "deploy/mesh/pull-config.ps1")
	mustContain(t, "deploy/mesh/pull-config.ps1", ps, "core.fsmonitor=false", "fsmonitor executes on fetch")
	mustContain(t, "deploy/mesh/pull-config.ps1", ps, "core.hooksPath=", "hooks execute on fetch/reset")
}

// TestReleaseTestsRunOutsideTheSigningJob pins the release fix: the job that
// holds id-token/contents/packages write must not execute the repository's test
// suite, or ordinary test code can reach the signing identity.
func TestReleaseTestsRunOutsideTheSigningJob(t *testing.T) {
	body := readDeploymentFile(t, ".github/workflows/release.yml")
	mustContain(t, ".github/workflows/release.yml", body, "needs: test", "the release job must depend on a separate test job")
	mustContain(t, ".github/workflows/release.yml", body, "permissions:\n      contents: read", "the test job must be read-only")

	// The release job must not run `go test` after the split.
	release := body[strings.Index(body, "  release:"):]
	if strings.Contains(release, "go test") {
		t.Error(".github/workflows/release.yml: the signing job must not execute the repository's test suite")
	}
}

// TestWindowsGuideRejectsMachineScopeCredentials pins the documentation fix:
// machine-wide variables are readable by every local user and the uninstaller
// does not remove them, so the guide must not offer them as equivalent.
func TestWindowsGuideRejectsMachineScopeCredentials(t *testing.T) {
	body := readDeploymentFile(t, "docs/windows-service.md")
	mustContain(t, "docs/windows-service.md", body, "Do **not** use machine-wide", "machine scope must be explicitly rejected")
	if strings.Contains(body, "machine-wide (System Properties") {
		t.Error("docs/windows-service.md: still presents machine-wide variables as an equivalent delivery path")
	}
}

// TestGitignoreCoversKeyMaterial pins the forward guard. The audit found a
// live targets.json still retrievable from history after it was untracked:
// untracking does not remove the blob, so the ignore list must cover the
// files the binary consumes before they are ever committed.
func TestGitignoreCoversKeyMaterial(t *testing.T) {
	body := readDeploymentFile(t, ".gitignore")
	for _, want := range []string{"targets.json", "dev_push.sh", ".env", "*.key", "*.pem", "*.p12", "*.pfx", "credentials*"} {
		mustContain(t, ".gitignore", body, want, "the forward guard must cover this path")
	}
}
