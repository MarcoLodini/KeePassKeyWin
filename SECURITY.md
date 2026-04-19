# Security Policy

## Supported versions

PassKee is pre-1.0 software. Only the latest commit on `master` is supported.
Tagged releases will be announced separately once v1.0 ships.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

PassKee brokers FIDO2 / WebAuthn credentials between Windows and a KeePass
vault. A bug in the wrong place could compromise user passkeys, so we take
disclosure seriously.

Report vulnerabilities privately via one of these channels, in order of
preference:

1. **GitHub private vulnerability reports** — open a report at
   <https://github.com/marcolodini/PassKee/security/advisories/new>.
   Preferred because it keeps the coordination thread attached to the repo.
2. **Email** — `marco.lodini@atechnordary.cloud` with subject line beginning
   `[PassKee SECURITY]`. Please encrypt sensitive reports with the
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

## Scope

In scope:

- The PassKee plugin (`src/PassKee.Plugin/`), core (`src/PassKee.Core/`),
  and Rust sidecar (`src/PassKee.Provider/`).
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
