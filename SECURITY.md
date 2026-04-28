# Security Policy

## Supported versions

KeePassKeyWin is pre-1.0 software. Only the latest commit on `master` is supported.
Tagged releases will be announced separately once v1.0 ships.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

KeePassKeyWin brokers FIDO2 / WebAuthn credentials between Windows and a KeePass
vault. A bug in the wrong place could compromise user passkeys, so we take
disclosure seriously.

Report vulnerabilities privately via one of these channels, in order of
preference:

1. **GitHub private vulnerability reports** — open a report at
   <https://github.com/marcolodini/KeePassKeyWin/security/advisories/new>.
   Preferred because it keeps the coordination thread attached to the repo.
2. **Email** — `marco.lodini@atechnordary.cloud` with subject line beginning
   `[KeePassKeyWin SECURITY]`. Please encrypt sensitive reports with the
   maintainer's OpenPGP key:

   - **Fingerprint**: `EA3C F4AA 91CE FAC5 68CF  8894 A8BF FD77 FA72 0913`
   - **Public key**: <https://github.com/marcolodini.gpg>, or import from a
     public keyserver:

     ```
     gpg --keyserver hkps://keys.openpgp.org \
         --recv-keys EA3CF4AA91CEFAC568CF8894A8BFFD77FA720913
     ```

   Always verify the full fingerprint out-of-band before trusting the key —
   do not rely on the short key ID. If your report is time-sensitive and
   you cannot encrypt it, send it plaintext rather than delay disclosure.

Please include:

- A description of the issue and the potential impact.
- Steps to reproduce (minimal PoC is ideal).
- Affected version / commit hash.
- Your preferred disclosure timeline, if any.

## What to expect

- Acknowledgement within **7 days** of the initial report.
- Triage + severity assessment within **14 days**.
- A fix (or a public advisory explaining why the issue will not be fixed)
  within **90 days** of the initial report, unless coordinated otherwise.

If no response is received within 14 days of your report, please escalate by
opening a minimal GitHub issue that says only "I sent a private security
report on YYYY-MM-DD and have not heard back" — no technical details.

## Trust model

KeePassKeyWin is two processes communicating over a per-session named pipe:
the MSIX-packaged Rust **sidecar** (COM-activated by `webauthn.dll`) and the
.NET Framework 4.8 **plugin** (loaded into KeePass). The pipe is ACL'd to the
current user's SID; both processes run as the same user. The trust model
treats the sidecar as **untrusted for security-critical claims** — the plugin
verifies any input that decides whether a credential operation proceeds.

**What the plugin verifies independently** (cryptographic, fail-closed):

- The MSIX **package family name** of whatever process opens the pipe must
  equal `KeePassKeyWin.Provider_4fv17arhjxxvg`, checked in the
  `keepasskeywin.hello` handshake.
- A per-launch **handshake nonce** (32 random bytes, single-use, written by
  the plugin to `HKCU\Software\KeePassKeyWin\HandshakeNonce` on
  `Initialize()` and deleted on first successful hello).
- `pbRequestSignature` over `SHA-256(pbEncodedRequest)` on every
  `makeCredentialRaw` / `getAssertionRaw` dispatch — the plugin re-computes
  the digest from the forwarded CBOR bytes and verifies against the cached
  Windows op-signing public key (Phase 5.UV.2+; sole verifier since 5.UV.5
  removed the sidecar-side gate).
- For v2-tier UV dispatches, the **UV response signature** against the same
  op-signing public key, accepting both IEEE P1363 and DER ECDSA-Sig-Value
  formats (Phase 5.UV.4+).
- For v1-tier UV dispatches (Windows builds where v2 is unavailable, or
  `webauthn.dll` returns `E_NOTIMPL` from the v2 entrypoint as on Win11 24H2
  build 26100.6725+), a once-per-plugin-process **Yes/No confirmation dialog**
  is the integrity substitute — v1's UV response covers no caller-supplied
  buffer and cannot be verified cryptographically.

**What the plugin sources from the sidecar without re-deriving** (input
material, not authorisation):

- The raw `pbEncodedRequest` CBOR bytes (the input that gets verified).
- The raw signature bytes (`pbRequestSignatureB64`, `uvSignatureB64`).
- The `uvBindingTier` string that selects the UV-gate branch — fail-closed
  on unknown values.
- The Windows op-signing public key, distributed once via the hello
  handshake's `opSignPublicKeyB64` field. Provenance: the sidecar fetches
  it via `WebAuthNPluginGetOperationSigningPublicKey(REFCLSID)` from
  `webauthn.dll`. The handshake nonce + package-family check above prove
  the sidecar that delivered the key is the right MSIX identity.
- The user-presence / user-verification boolean (`uv`), which is reflected
  into the `UV` flag in the assertion's `authData`.

**Out of model:** an attacker with code execution as the current user can
forge the op-signing signature (the per-process op-signing key is held by
`webauthn.dll`), can read or modify `HKCU` to retrieve the handshake nonce,
and can register their own MSIX with a colliding package family name on a
machine they already own. The trust boundary is **defence in depth against
non-MSIX local processes**; it is *not* a substitute for the user's KeePass
master password, which always gates access to private key material at rest.

The vault's private keys never leave the plugin process: on `GetAssertion`
the sidecar forwards `authData || clientDataHash`, the plugin signs in-process,
and only the signature bytes return. Compromising the sidecar yields request
inputs and the ability to elicit Windows Hello prompts; it does not yield the
private keys.

A debug-only emergency bypass for the request-signature gate exists
(`KEEPASSKEYWIN_SKIP_PLUGIN_SIG_VERIFY=1`); enabling it logs a loud warning
and is not for production use. There is no debug bypass for the UV gate.

See `docs/ARCHITECTURE.md` § "Trust boundaries and signature verification"
for the architectural diagram, and `docs/IPC_PROTOCOL.md` for the on-the-wire
field schemas.

## Scope

In scope:

- The KeePassKeyWin plugin (`src/KeePassKeyWin.Plugin/`), core (`src/KeePassKeyWin.Core/`),
  and Rust sidecar (`src/KeePassKeyWin.Provider/`).
- The IPC protocol between them (`docs/IPC_PROTOCOL.md`).
- The MSIX manifest and COM registration flow.

Out of scope:

- Vulnerabilities in KeePass itself — report upstream to the KeePass project.
- Vulnerabilities in Windows WebAuthn, `webauthn.dll`, or the
  `IPluginAuthenticator` API — report to Microsoft via MSRC.
- Vulnerabilities in third-party Rust or NuGet dependencies — report
  upstream; we will pick up fixes via dependency updates.
- Social engineering, physical access, or attacks that require the user to
  unlock their vault first (the KeePass threat model already covers these).

## Safe-harbour

We will not pursue legal action against researchers who:

- Act in good faith to identify and report vulnerabilities.
- Avoid privacy violations, destruction of data, and disruption of user
  systems.
- Give us reasonable time to fix issues before public disclosure.
