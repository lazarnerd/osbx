---
name: osbx-release
description: >-
  Use this skill when the user asks to release a new version of osbx, bump the
  workspace version, open a release PR, or publish a GitHub Release with Flatpak
  and Debian packages.
---

# Releasing `osbx`

Follow this procedure when releasing a new version of `osbx`.

## Steps

1. **Verify integration tests and cross-target gates first**
   - Build the Windows guest agent if Windows agent code changed:
     `cargo build --release -p osbx-agent --target x86_64-pc-windows-gnu`
   - Run formatting, Linux + Windows clippy, workspace tests, and relevant integration tests:
     ```bash
     cargo fmt --all -- --check
     cargo clippy --workspace --all-targets -- -D warnings
     cargo clippy -p osbx-vmm -p osbx-sandbox -p osbx-agent -p osbx-cli --target x86_64-pc-windows-gnu --all-targets -- -D warnings
     cargo test --workspace --no-fail-fast
     cargo test -p osbx-sandbox --test file_sync -- --nocapture
     cargo test -p osbx-cli --test windows_backends -- --nocapture
     ```

2. **Bump version**
   - Update `[workspace.package].version` in `Cargo.toml` (single source of truth for workspace crates).
   - Refresh `Cargo.lock` with `cargo check --workspace`.

3. **Commit on a feature branch & open a PR**
   - Stage only tracked/intended project files (exclude untracked local files such as `osbx-compose.yml`).
   - Push the feature branch and open a PR targeting `main`:
     `gh pr create --base main --head <branch> ...`
   - Watch all 4 CI matrix jobs until green (`ci.yml` runs on every push/PR to `main`):
     `gh pr checks <PR_NUMBER> --watch --interval 10`

4. **Wait for user merge (respect branch protection)**
   - Never push directly to `main` and never pass `--admin` to `gh pr merge`.
   - Ask the user to review and merge the PR on GitHub.

5. **Tag `vX.Y.Z` on merged `origin/main` and verify the release workflow**
   - Fetch `origin/main`, create an annotated tag on `origin/main`, and push the tag:
     ```bash
     git fetch origin main
     git tag -a vX.Y.Z origin/main -m "Release vX.Y.Z: <summary>"
     git push origin vX.Y.Z
     ```
   - **Do not** rely on `gh release create` with a token lacking release-write scope: pushing a `v*` tag triggers `.github/workflows/flatpak.yml`, which builds `osbx-X.Y.Z-x86_64.flatpak`, `osbx.flatpakrepo`, and `osbx_X.Y.Z_amd64.deb`, creates/attaches them to the GitHub Release using `GITHUB_TOKEN`, and deploys the GitHub Pages Flatpak repo.
   - Watch the workflow and verify attached assets:
     ```bash
     RUN_ID=$(gh run list --workflow flatpak.yml --limit 1 --json databaseId,headBranch -q '.[] | select(.headBranch=="vX.Y.Z") | .databaseId' | head -n 1)
     gh run watch "$RUN_ID" --exit-status
     gh release view vX.Y.Z --json url,assets -q '{url: .url, assets: [.assets[].name]}'
     ```
