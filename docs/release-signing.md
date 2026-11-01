# Signing the Windows executables

The release pipeline already produces three pieces of evidence that the
binaries are the ones this repository built:

- a keyless **cosign** signature over `checksums.txt` (Sigstore bundle),
- a **SLSA build-provenance** attestation for the same checksums,
- GoReleaser checksums for every archive and bare binary.

None of them is understood by Windows. SmartScreen, Smart App Control,
AppLocker/WDAC, PowerShell's execution policy and enterprise EDR all evaluate
**Authenticode**, a PE signature chaining to a CA in the Microsoft Trusted Root
Program. `gh attestation verify` and `cosign verify-blob` tell a careful
operator that the download is genuine; an Authenticode signature is what stops
a user from being prompted at all.

This page covers how to get that signature and how the repository is wired for
it.

## What the repository does today

`installer/windows/sign-windows.sh` signs every Windows binary during
GoReleaser's **post-build** hook (`.goreleaser.yaml`), i.e. before the binary is
wrapped in a zip — signing the archive afterwards would leave the `.exe` inside
unsigned. The hook is a deliberate no-op when no certificate is configured:

```text
sign-windows: no signing certificate configured; Windows binaries are left UNSIGNED (SmartScreen will warn).
```

so `goreleaser build --snapshot` and any developer build keep working. In the
release workflow the hook is enabled only when the repository variable
`WINDOWS_AUTHENTICODE` is `true`, and `WINDOWS_SIGN_REQUIRED=1` then turns a
missing or broken certificate into a failed release instead of a silently
unsigned one.

The script uses [osslsigncode](https://github.com/mtrojnar/osslsigncode) (GPL-3,
the standard open-source Authenticode signer) and verifies its own output. The
hook is invoked through `sh`, so a native Windows `goreleaser` run needs a POSIX
shell (WSL, Git Bash); official releases build on `ubuntu-latest`.
`sh -n` and the argument/no-op paths are exercised by the test suite; actual
signing needs a certificate, which is an operator secret.

| Variable | Meaning |
|---|---|
| `WINDOWS_SIGN_PFX` | PKCS#12 bundle with the leaf certificate and key (used by the workflow) |
| `WINDOWS_SIGN_PFX_PASS` | its password |
| `WINDOWS_SIGN_CERT` / `WINDOWS_SIGN_KEY` | PEM pair, alternative to the PFX |
| `WINDOWS_SIGN_TS` | RFC 3161 timestamp URL (default `http://timestamp.digicert.com`; empty disables) |
| `WINDOWS_SIGN_REQUIRED` | `1` = fail instead of no-op when unconfigured |
| `WINDOWS_SIGN_DESC` / `WINDOWS_SIGN_URL` | text shown in the UAC/SmartScreen prompt |

Always keep a timestamp. Without one, the signature becomes invalid the moment
the certificate expires, and every deployed copy would need re-signing and
re-releasing.

## Choosing a certificate

There is no free certificate authority for code signing. Let's Encrypt issues
TLS certificates only, and since June 2023 publicly trusted OV/EV code-signing
keys must live on FIPS 140-2 hardware (a USB token or a cloud HSM), so a
downloadable `.pfx` no longer exists from a commercial CA. The realistic
options:

### 1. SignPath Foundation — free, publicly trusted, for OSS

[SignPath Foundation](https://signpath.org/) obtains an OV code-signing
certificate **issued to the Foundation** and lets qualifying OSS projects use
it, with the private key in their HSM. It is the usual answer to "how do I sign
an open-source Windows binary for free".

- **Cost:** free for OSS.
- **Trust:** public — SmartScreen/AppLocker accept it. The publisher shown is
  *SignPath Foundation* on behalf of the project, not the maintainer.
- **Eligibility:** OSI-approved licence, public actively-developed repository,
  no proprietary components, no malware. This repository is GPL-3.0, so it
  qualifies on licence.
- **Requires:** MFA on SignPath and GitHub, named signing roles, a repository
  page headed **Code signing policy** naming the committers/reviewers/approvers
  and stating "Free code signing provided by SignPath.io, certificate by
  SignPath Foundation", and a manual approval for each signing request.
- **Integration:** GitHub Action `SignPath/github-action-submit-signing-request`
  plus an artifact-configuration XML; the release flow becomes
  build → submit → approve → download signed artifact → publish. That is a
  larger restructuring than the hook below, and it cannot be tested without an
  approved SignPath project, so it is documented here rather than pre-wired.

If you want this path, apply at <https://signpath.org/apply> and then replace
the GoReleaser post hook with a SignPath signing step. Keep the hook's
no-op-when-unconfigured behaviour.

### 2. Azure Artifact Signing (formerly Trusted Signing) — cheap, managed

Microsoft's managed signer, ~US$9.99/month for up to 5,000 signatures. It
issues short-lived certificates from a Microsoft CA and integrates through
`azure/trusted-signing-action`.

- **Eligibility (2026):** organisations in the USA, Canada, the EU and the UK;
  individual developers in the USA and Canada only. **Australia is not on the
  list**, so for this maintainer it is not currently an option.
- **Trust:** public, non-EV. No instant SmartScreen reputation: it accumulates
  with download volume, exactly like an OV certificate.

### 3. Commercial OV/EV certificate

A CA-issued certificate in your own legal name, US$300–500/year, delivered on a
hardware token or through a cloud HSM (DigiCert KeyLocker, Sectigo, SSL.com).
This is the only option that gives a publicly trusted signature under the
maintainer's own identity, and the only one available worldwide. The PFX path
in `sign-windows.sh` covers the cloud-HSM/exportable variants; token-based keys
need the CA's tooling or PKCS#11 (`osslsigncode -pkcs11cert/-key`).

### 4. Self-signed / private CA — free, no public trust

A certificate this project issues itself costs nothing and uses only
open-source tooling, but Windows does not trust it. It becomes usable when the
root is deployed to the machines:

- **Domain/enterprise fleets** (this project's usual deployment): publish the
  root certificate through GPO, Intune or the Ansible play, then Authenticode
  verifies on every managed host and AppLocker/WDAC allowlisting works.
- **Unmanaged machines:** SmartScreen still warns; a self-signed signature buys
  nothing there. Do not ship it to the public as if it were trusted.

Generate a private signing identity (keep the CA key offline):

```sh
# CA (once, offline)
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout ca.key -out ca.pem -subj "/CN=Example Corp Code Signing CA/O=Example Corp"

# Leaf (renew yearly, keep it on the release runner only as a secret)
openssl req -newkey rsa:3072 -nodes -keyout sign.key -out sign.csr \
  -subj "/CN=Link Ping Prometheus/O=Example Corp"
openssl x509 -req -in sign.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 365 -out sign.pem \
  -extfile <(printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n')

openssl pkcs12 -export -inkey sign.key -in sign.pem -certfile ca.pem \
  -out windows-sign.pfx
base64 -w0 windows-sign.pfx   # -> repository secret WINDOWS_SIGN_PFX_B64
```

Then set the repository variable `WINDOWS_AUTHENTICODE=true`, add the secret
`WINDOWS_SIGN_PFX_B64` (and `WINDOWS_SIGN_PFX_PASS` if the bundle has one), and
deploy `ca.pem` to the fleet's Trusted Root store.

## Verifying a signature

```sh
osslsigncode verify -in link_ping_prometheus_Windows_x86_64.zip   # archives: extract first
osslsigncode verify -in link_ping_prometheus.exe
```

```powershell
Get-AuthenticodeSignature .\link_ping_prometheus.exe | Format-List Status, StatusMessage, SignerCertificate
```

`Status: Valid` means the chain is trusted on that machine. A self-signed
certificate reports `UnknownError`/`UntrustedRoot` until its CA is deployed.

## Summary

| Option | Cost | Public trust | Fits this project |
|---|---|---|---|
| SignPath Foundation | free | yes (publisher: SignPath Foundation) | best free option; needs an application and a policy page |
| Azure Artifact Signing | ~$10/mo | yes (non-EV) | not eligible from Australia |
| Commercial OV/EV | $300–500/yr | yes, own identity | the worldwide fallback |
| Self-signed / private CA | free | no (unless the root is deployed) | good for the Ansible-managed fleets; not for public downloads |

The signing hook is in place and inert until a certificate is configured, so
adopting any of these is a secrets/variables change plus (for SignPath) a
workflow step — not a code change.
