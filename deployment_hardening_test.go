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
	// actions/checkout on the windows-latest runner leaves core.autocrlf at
	// its default, so these files arrive with CRLF. Normalise before any
	// multi-line assertion; the shipped bytes are LF and CI must not depend
	// on the runner's git configuration.
	return strings.ReplaceAll(string(b), "\r\n", "\n")
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

// TestWindowsInstallerUsesTheSCMEnvironmentValue pins both halves of the
// Windows credential mechanism, which the audit found shipped broken:
//
//   - the SCM reads a REG_MULTI_SZ VALUE named Environment on the service key,
//     not a same-named SUBKEY (a subkey silently delivered nothing: metrics
//     auth stayed off and HMAC was never enabled while the config looked right);
//   - the service key inherits BUILTIN\Users read from ...\Services, so it is
//     protected BEFORE the value is written, and a cleared variable REMOVES its
//     entry so a retired secret does not survive.
func TestWindowsInstallerUsesTheSCMEnvironmentValue(t *testing.T) {
	path := "installer/windows/install-service.bat"
	body := readDeploymentFile(t, path)

	mustContain(t, path, body, "PropertyType MultiString", "the SCM reads a REG_MULTI_SZ value")
	mustContain(t, path, body, "Remove-ItemProperty -Path $k -Name Environment", "cleared credentials must be removed")
	mustContain(t, path, body, "SetSecurityDescriptorSddlForm", "the service key must be protected")
	mustNotContain(t, path, body, `reg add "%ENV_KEY%"`, "a subkey write is ignored by the SCM")
	mustNotContain(t, path, body, `\Environment /v`, "a subkey write is ignored by the SCM")

	acl := indexOf(t, path, body, "SetSecurityDescriptorSddlForm")
	write := indexOf(t, path, body, "New-ItemProperty -Path $k -Name Environment")
	if acl > write {
		t.Errorf("%s: the service key must be protected before the credential value is written", path)
	}

	// A metrics credential the runtime gate rejects must stop the install
	// before the value is written or the service is started.
	mustContain(t, path, body, "metrics basic-auth credentials were entered, but the service arguments include", "refuse credentials without TLS/allow-insecure")
	guard := indexOf(t, path, body, "if not defined METRICS_TRANSPORT_OK")
	startService := indexOf(t, path, body, "=== Starting service ===")
	if guard > startService {
		t.Errorf("%s: the metrics credential guard must run before the service is started", path)
	}
	if guard > write {
		t.Errorf("%s: the metrics credential guard must run before any credential is written", path)
	}
	// The installed bytes are verified against the source after the copy.
	mustContain(t, path, body, "does not match \"%EXE_PATH%\" after the copy", "verify the copied binary")
}

// TestAnsibleReconcilesTheSCMEnvironmentValue pins the play-side mechanism:
// one REG_MULTI_SZ Environment value on the protected service key, entries
// preserved, cleared variables REMOVED from it. The old win_regedit loop wrote
// a subkey the SCM ignores.
func TestAnsibleReconcilesTheSCMEnvironmentValue(t *testing.T) {
	for _, path := range []string{"deploy/ansible/playbook.yml", "deploy/ansible/mesh.yml"} {
		body := readDeploymentFile(t, path)
		mustContain(t, path, body, "PropertyType MultiString", "the SCM reads a REG_MULTI_SZ value")
		mustContain(t, path, body, "$m.Remove($p[0])", "a cleared variable must be removed, not left installed")
		mustContain(t, path, body, "SetSecurityDescriptorSddlForm", "the service key must be protected")
		mustNotContain(t, path, body, "ansible.windows.win_regedit", "a win_regedit subkey is ignored by the SCM")
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

// TestMeshGuideOwnsThePullDirectory pins the documented manual Windows recipe:
// following it with an unmanaged ProgramData container reintroduces the
// SYSTEM-executes-a-user-writable-directory problem that the play now fixes.
func TestMeshGuideOwnsThePullDirectory(t *testing.T) {
	body := readDeploymentFile(t, "docs/mesh-deployment.md")
	mustContain(t, "docs/mesh-deployment.md", body, "takeown.exe /f $data /a", "the manual recipe must take ownership")
	mustContain(t, "docs/mesh-deployment.md", body, "icacls.exe $data /inheritance:r", "the manual recipe must drop inherited ACEs")
}

// TestSecurityDocDocumentsTheWeakModes pins the two operational modes that are
// bounded but real: header-only tag coverage and secret-less allowlist
// authentication.
func TestSecurityDocDocumentsTheWeakModes(t *testing.T) {
	body := readDeploymentFile(t, "docs/security.md")
	mustContain(t, "docs/security.md", body, "v0.7 interop escape hatch", "header coverage must be documented as interop-only")
	mustContain(t, "docs/security.md", body, "targeted\n    \"100% loss\"", "secret-less budget spoofing must be documented")
}

// TestWindowsSigningIsWiredAndInert pins the Authenticode plumbing: GoReleaser
// must sign each Windows binary BEFORE it is archived (signing the zip would
// leave the exe inside unsigned), the hook must be a no-op when no certificate
// is configured (so developer/snapshot builds keep working), and the release
// workflow must gate signing on a repository variable rather than failing every
// release until secrets exist.
func TestWindowsSigningIsWiredAndInert(t *testing.T) {
	gr := readDeploymentFile(t, ".goreleaser.yaml")
	mustContain(t, ".goreleaser.yaml", gr, "sign-windows.sh", "the post-build hook must call the signer")
	mustContain(t, ".goreleaser.yaml", gr, "hooks:", "signing must run before archiving")

	script := readDeploymentFile(t, "installer/windows/sign-windows.sh")
	mustContain(t, "installer/windows/sign-windows.sh", script, "no signing certificate configured", "an unconfigured run must be a no-op")
	mustContain(t, "installer/windows/sign-windows.sh", script, "WINDOWS_SIGN_REQUIRED", "CI must be able to make it fatal")
	mustContain(t, "installer/windows/sign-windows.sh", script, "Number of verified signatures: 1", "the script must verify its own output (exit code alone fails for self-signed)")

	wf := readDeploymentFile(t, ".github/workflows/release.yml")
	mustContain(t, ".github/workflows/release.yml", wf, "vars.WINDOWS_AUTHENTICODE == 'true'", "signing must be opt-in")
	mustContain(t, ".github/workflows/release.yml", wf, "WINDOWS_SIGN_REQUIRED", "the release must fail if signing is enabled but unconfigured")
	mustContain(t, ".github/workflows/release.yml", wf, "OSSL_SHA=", "the signer must be pinned")

	doc := readDeploymentFile(t, "docs/release-signing.md")
	mustContain(t, "docs/release-signing.md", doc, "SignPath Foundation", "the free OSS option must be documented")
	mustContain(t, "docs/release-signing.md", doc, "Azure Artifact Signing", "the managed option must be documented")
}

// TestCodeSigningPolicyIsComplete pins the SignPath Foundation requirements a
// reviewer checks before accepting a project: the exact statement, the three
// named roles, a privacy policy, the "not a hacking tool" clarification, and
// the term "Code signing policy" on the home page.
func TestCodeSigningPolicyIsComplete(t *testing.T) {
	policy := readDeploymentFile(t, "CODE_SIGNING_POLICY.md")
	mustContain(t, "CODE_SIGNING_POLICY.md", policy,
		"Free code signing provided by [SignPath.io](https://about.signpath.io),",
		"the required statement")
	mustContain(t, "CODE_SIGNING_POLICY.md", policy, "certificate by [SignPath Foundation](https://signpath.org)", "the required statement")
	for _, role := range []string{"**Authors**", "**Reviewers**", "**Approvers**"} {
		mustContain(t, "CODE_SIGNING_POLICY.md", policy, role, "SignPath requires named roles")
	}
	mustContain(t, "CODE_SIGNING_POLICY.md", policy, "transfers no information to other networked systems", "privacy policy")
	mustContain(t, "CODE_SIGNING_POLICY.md", policy, "not a security\nscanner", "the no-hacking-tools clause needs an explicit answer")

	readme := readDeploymentFile(t, "README.md")
	mustContain(t, "README.md", readme, "## Code signing policy", "the home page must name the policy")
	mustContain(t, "README.md", readme, "CODE_SIGNING_POLICY.md", "the home page must link the policy")
}

// TestSignPathArtifactConfigurationMatchesTheBuild pins the artifact config
// against what the build actually produces: the archive root holds the exe and
// the metadata restrictions match the values gen-versioninfo.sh embeds. A
// mismatch makes every signing request fail at SignPath.
func TestSignPathArtifactConfigurationMatchesTheBuild(t *testing.T) {
	cfg := readDeploymentFile(t, ".signpath/artifact-configuration.xml")
	mustContain(t, ".signpath/artifact-configuration.xml", cfg, `path="link_ping_prometheus.exe"`, "the exe sits at the zip root")

	gen := readDeploymentFile(t, "installer/windows/gen-versioninfo.sh")
	mustContain(t, "installer/windows/gen-versioninfo.sh", gen, `-product-name "Link Ping Prometheus"`, "product name must match the artifact config")
	mustContain(t, "installer/windows/gen-versioninfo.sh", gen, `-original-name "link_ping_prometheus.exe"`, "original filename must match")

	gr := readDeploymentFile(t, ".goreleaser.yaml")
	mustContain(t, ".goreleaser.yaml", gr, "gen-versioninfo.sh", "the version resource must be generated before builds")

	// The release body carries the required statement on every download page.
	wf := readDeploymentFile(t, ".github/workflows/release.yml")
	mustContain(t, ".github/workflows/release.yml", wf, "certificate by [SignPath Foundation]", "release pages must carry the statement")
}

// TestLongTermRunbookCoversBothPlatforms pins the two-node runbook: it must
// describe the Linux and Windows sides, warn about the one-sided-secret trap,
// and give a daily check that reads /status and /metrics on both.
func TestLongTermRunbookCoversBothPlatforms(t *testing.T) {
	doc := readDeploymentFile(t, "docs/long-term-test.md")
	mustContain(t, "docs/long-term-test.md", doc, "-mode=client", "the prober side must be documented")
	mustContain(t, "docs/long-term-test.md", doc, "**Windows prober:**", "the Windows side must be documented")
	mustContain(t, "docs/long-term-test.md", doc, "/status", "daily checks read the process snapshot")
	mustContain(t, "docs/long-term-test.md", doc, "replay window is ±30 s", "clock sync is load-bearing")
	mustContain(t, "docs/long-term-test.md", doc, "one-sided secret", "the half-configured trap must be called out")

	index := readDeploymentFile(t, "docs/README.md")
	mustContain(t, "docs/README.md", index, "long-term-test.md", "the runbook must be in the docs index")
}
