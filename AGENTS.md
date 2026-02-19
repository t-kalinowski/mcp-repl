
- If you modified code, before responding to the user, always run all tests, lints, and checks and make sure everything succeeds and returns cleanly:
  - cargo check
  - cargo build
  - cargo clippy
  - cargo test
  - cargo +nightly fmt

- Project convention: never pass `--vanilla` to `R`/`Rscript` commands unless the user explicitly asks for it.

- Snapshot tests (insta):
  - Preferred local loop:
    - `cargo insta test`
    - `cargo insta pending-snapshots`
    - `cargo insta review` (interactive) or `cargo insta accept` / `cargo insta reject` (non-interactive)
  - CI-style validation: `cargo insta test --check --unreferenced=reject`
  - For intentional snapshot format/metadata migrations: `cargo insta test --force-update-snapshots --accept`
  - Bulk rewrite fallback (for intentional broad refreshes): `INSTA_UPDATE=always cargo test`
  - Do not manually delete `tests/snapshots/*.snap.new`; use `cargo insta reject` to clean pending snapshots canonically.
  - `cargo insta ...` requires the `cargo-insta` subcommand.

At any time, you may consult the R source code at `~/github/wch/r-source` and the Python source code at `~/github/python/cpython` to investigate and resolve questions.
