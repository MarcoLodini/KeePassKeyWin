# KeePassKeyWin — To Do

## Self-signed certificate setup (one-time, pre-first-release)

- [ ] **Generate development certificate** by running `ensure-dev-cert.ps1`
      (creates a self-signed PFX trusted on the local machine).

- [ ] **Add GitHub repo secrets**:
  - `DEV_CERTIFICATE` — Base64-encoded PFX contents
  - `DEV_CERTIFICATE_PASSWORD` — password used when generating the PFX
