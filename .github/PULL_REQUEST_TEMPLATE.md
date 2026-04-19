## Summary

<!-- What changed and why. Keep it short; link to the issue or design doc for deeper context. -->

## Related issue

<!-- Fixes #123 — or delete this section. -->

## Test plan

<!-- Check everything that applies. Runtime-affecting changes need a live Windows validation bullet. -->

- [ ] `dotnet test --nologo` passes locally
- [ ] `cargo test --all-targets` passes locally (run from `src/KeePassKeyWin.Provider/`)
- [ ] `cargo xwin build --target x86_64-pc-windows-msvc --release` green (sidecar changes only)
- [ ] Live Windows validation — describe the flow, Windows build, browser, and RP used
- [ ] Docs / CI / tooling only — no runtime behavior change

## Checklist

- [ ] No secrets or credentials in the diff
- [ ] Relevant docs updated (`README.md`, `docs/PLAN.md`, `docs/ARCHITECTURE.md`, `docs/WINDOWS_VALIDATION.md`)
- [ ] New landmines / non-obvious constraints captured as inline comments explaining the **why**
