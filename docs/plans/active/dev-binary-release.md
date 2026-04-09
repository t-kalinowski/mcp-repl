# Rolling Dev Binary Release

## Summary

- Add a rolling published prerelease named `dev` on GitHub Releases.
- Keep semver releases unchanged and keep GitHub Actions artifacts as an internal handoff only.
- Extend the existing CI workflow instead of introducing a separate release workflow.

## Status

- State: active
- Last updated: 2026-04-08
- Current phase: implementation

## Current Direction

- Add release-mode packaging to every existing CI matrix job so packaging failures are visible on PRs and `main`.
- On `push` to `main`, upload one packaged workflow artifact per first-class platform and gate publication behind a serialized `publish-dev` job that only updates `dev` when the current run is the newest successful push-to-`main` run.
- Lock the public download contract in `README.md` and a docs contract test so stable asset names and URLs stay intentional.

## Long-Term Direction

- Keep `dev` as the mutable prerelease channel and keep stable semver releases as immutable user-facing milestones.
- If the project later needs broader platform coverage or stronger Linux portability, add new assets or a separate build strategy without changing the meaning of the `dev` channel.

## Phase Status

- Phase 0: completed
- Phase 1: active
- Phase 2: pending

## Locked Decisions

- The public download surface is GitHub Releases, not Actions artifacts.
- The `dev` channel is a published prerelease and must not become the repository's latest stable release.
- v1 covers Linux x86_64 glibc on Ubuntu 22.04, macOS arm64, and Windows x86_64 with stable asset names.

## Open Questions

- None for this implementation slice.

## Next Safe Slice

- Add a docs contract test for the `dev` binary download surface, then update `ci.yml` and `README.md` to satisfy it.

## Stop Conditions

- Stop and update the plan if the existing workflow structure cannot support the publish gating without a separate workflow.
- Stop and update the plan if GitHub-hosted runner assumptions for any required platform change during implementation.

## Decision Log

- 2026-04-08: Chose a single-workflow design so the existing PR/main validation path and the new rolling release path stay coupled.
- 2026-04-08: Chose a docs contract test as the first red-green slice because the public change is distribution-facing rather than a Rust API change.
