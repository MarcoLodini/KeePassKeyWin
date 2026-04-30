# KeePassKeyWin — To Do

## SignPath Foundation setup (one-time, pre-first-release)

- [ ] **Apply** at <https://signpath.io/product/open-source>
      (1–3 business days for approval; have repo URL + description ready)

- [ ] **Configure SignPath dashboard** after approval:
  - Create project `keepasskeywin`, link GitHub repo
  - Create signing policy `release-signing`, restrict to `master` + `release/*` branches
  - Add the artifact config from `.signpath/artifact-configurations/default.xml`
  - Link Trusted Build System: `GitHub.com`

- [ ] **Add GitHub repo secrets**:
  - `SIGNPATH_API_TOKEN` — generated from SignPath dashboard
  - `SIGNPATH_ORGANIZATION_ID` — visible in SignPath dashboard (click org name)

- [ ] **Install SignPath GitHub App** on the repo
      (SignPath dashboard will prompt you after project creation)
