# Release process

## Repository setup

Before Release Please can open a release pull request, enable **Allow GitHub
Actions to create and approve pull requests** in the repository's **Settings >
Actions > General > Workflow permissions**. Save the setting after you enable
it. The workflow already grants `GITHUB_TOKEN` the required `contents: write`,
`issues: write`, and `pull-requests: write` permissions, but those workflow
permissions do not enable this repository setting.

GitHub disables this setting by default for new personal repositories. An
organization policy can control the setting for repositories in that
organization. See [GitHub's repository Actions settings
documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests).

## Version and changelog pull requests

The `Release Please` workflow runs when commits reach `main`. It uses the
Conventional Commit title carried by each squash merge to decide whether to
open or update a release pull request and to write `CHANGELOG.md`.

- Use `feat:` for a feature and `fix:` for a bug fix. Use `feat!:` or `fix!:`
  when the change is breaking. Use another Conventional Commit type when the
  change should not trigger a release.
- Review the generated pull request's changelog and Cargo version updates.
  Release Please updates the root `baffle-proxy` version, workspace member
  versions, and `Cargo.lock` together. The client crate stays in the same
  workspace release.
- Merge the release pull request only after its required checks pass. The
  merge creates the `vX.Y.Z` tag and GitHub Release. Release Please handles
  versions and release notes; it does not build or upload the Linux archive.

If a release is needed but merged commit messages do not imply the intended
version, include a `Release-As: X.Y.Z` footer in the body of a commit that lands
on `main`. For a squash merge, preserve that footer in the squash commit body.
Release Please documents this footer as an explicit version override. Manually
dispatching the `Release Please` workflow can retry processing, but it does not
change how commits are classified.

## Crates.io packages

The workspace contains two packages for synchronized crates.io releases:

| Crate | Package role | Install or depend on it |
| --- | --- | --- |
| `baffle-proxy` | Daemon and `baffle` executable | `cargo install baffle-proxy --locked --bin baffle` |
| `baffle-client` | Typed client for the Unix control protocol | `baffle-client = "0.2"` in `[dependencies]` for the open release candidate |

Rust applications that use `baffle-client` also need Tokio with the runtime
features required by the application. The client package does not contain the
proxy daemon or send application traffic through the session data socket.

Both packages declare `license = "MIT"` and point to this repository. Each
package has its own README and a `docs.rs` documentation URL. The root
[`LICENSE`](../LICENSE) applies to Baffle's original code. The client package
contains the same MIT text so its archive can be used on its own. These
declarations do not change the licenses of crates that Baffle depends on. The
hand-built Linux binary release separately includes third-party license and
notice files for its bundled dependencies.

`baffle-proxy` keeps a local path to `baffle-client` and also declares the
matching registry version. The path supports workspace development. The
version lets Cargo resolve the client crate after `baffle-proxy` is published.
Keep the root package, workspace member, local dependency version, and lockfile
in sync. The existing Release Please `cargo-workspace` plugin merges the Rust
workspace updates into one release pull request. The current generated release
pull request was checked: it updates both package versions and `Cargo.lock`
together. The Release Please Cargo updater rewrites a local dependency's
version only when its entry has both `path` and `version`; this manifest
declares both. See the [Cargo workspace plugin
guide](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md#cargo-workspace)
and [Cargo manifest
updater](https://github.com/googleapis/release-please/blob/main/src/updaters/rust/cargo-toml.ts).
Review each generated release pull request to confirm that the
`baffle-client` dependency version also matches the new member version and that
the tag remains `vX.Y.Z`.

Crate names are allocated on a first-come basis. As of 2026-09-26,
`cargo search baffle-client` and `cargo search baffle-proxy` returned no
registered packages. Recheck both names immediately before the first publish.
Choose the crates.io account that will own the packages before enabling
automated publishing. That account must publish `baffle-client` first, then
`baffle-proxy`, and must grant the repository's intended release user or team
owner rights for both crates. After the first publish, verify each owner list
with `cargo owner --list <crate>` and add a GitHub user or team with
`cargo owner --add <github-user-or-team> <crate>` if required. Do not enable
automatic publication until the names and owners are confirmed and the
repository's `CARGO_REGISTRY_TOKEN` belongs to an account with publish rights
for both crates. Keep that token in GitHub Actions secrets. See the Cargo
[publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html)
for name allocation and owner management.

Before a release, run these package checks from the repository root:

```sh
cargo metadata --locked
cargo package --list --package baffle-client
cargo package --list --package baffle-proxy
cargo publish --dry-run --locked --package baffle-client
```

The client dry run packages, extracts, and builds the client crate without
publishing it. `baffle-proxy` can be inspected with `cargo package --list` even
before its dependency is in the registry. A full proxy dry run may need the
matching `baffle-client` version to be available on crates.io; the publication
workflow must publish the client first. Never use a real `cargo publish` as a
packaging check. Crates.io publication stays separate from the manually
dispatched Linux binary workflow and does not replace the `Format, lint, and
test` required check.

The action uses the repository's `GITHUB_TOKEN` with `contents: write`,
`issues: write`, and `pull-requests: write`. No PAT or GitHub App secret is
required.

## CI for generated release pull requests

GitHub does not start ordinary workflow runs for most events caused by
`GITHUB_TOKEN`. Release Please uses that token to create and update its pull
request. GitHub may hold the resulting pull request checks for approval, and a
tag created with that token does not trigger the tag-push packaging workflow.
`workflow_dispatch` is an exception to this suppression.

If the generated release pull request has no CI run, dispatch the existing Rust
CI workflow against its head branch. In GitHub Actions, open **Rust CI**, choose
**Run workflow**, select the release pull request's head branch, then run it.
The dispatch executes the same Rust, namespace integration, and required-check
jobs as the pull request event. The stable required job remains
`Format, lint, and test`. The CLI equivalent is
`gh workflow run ci.yml --ref <release-pr-head-branch>`.

## Manually package a release

After Release Please has created the tag and published the GitHub Release:

1. Open **Linux release** in GitHub Actions and choose **Run workflow** from
   `main`.
2. Enter the exact generated tag, such as `v0.2.0`.
3. Confirm the run checks out that tag, matches it to Cargo's package version,
   and finds the published release PR and GitHub Release.
4. Confirm the archive and `SHA256SUMS` appear as assets on the existing release.

The CLI equivalent is `gh workflow run release.yml --ref main -f tag=vX.Y.Z`.

The workflow preserves the existing Linux x86-64 archive contents, MIT license,
third-party notices, and checksum. It does not create a tag or GitHub Release.
If both expected assets already exist and match the newly built files, a rerun
skips upload. If the release contains only one expected asset or either asset
differs, the run fails without overwriting it.

The workflow also retains a tag-push trigger for human-created tags. That path
uses the same release, tag, version, and Release Please PR checks. Do not rely on
it for Release Please tags because GitHub suppresses ordinary tag-push workflow
runs caused by `GITHUB_TOKEN`.

## Safe local binary packaging check

To verify the existing Linux binary packaging without creating a GitHub
release, read the current daemon version from Cargo metadata and run the
packaging script. This creates only local files under `dist/`:

```sh
version=$(cargo metadata --locked --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "baffle-proxy") | .version')
./scripts/package-release.sh "v${version}"
tar -tzf "dist/baffle-proxy-v${version}-x86_64-unknown-linux-gnu.tar.gz"
(cd dist && sha256sum -c SHA256SUMS)
```

This safe check exercises the Cargo version and MIT license gates, Linux build,
archive contents, and checksum generation. It does not simulate a GitHub tag or
upload assets.
