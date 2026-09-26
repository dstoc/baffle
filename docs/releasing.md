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
- Merge the release pull request only after the generated-candidate checks
  below succeed. The merge creates the `vX.Y.Z` tag and GitHub Release. The
  same Release Please workflow run then verifies that release and publishes
  `baffle-client` followed by `baffle-proxy` to crates.io.
- Linux binary assets remain a separate, manual step. Use the **Linux release**
  workflow after the crates.io publication run succeeds.

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
The Release Please manifest tracks both crates at their current versions. The
`linked-versions` plugin keeps them at the same version. The
`cargo-workspace` plugin runs with `merge: false`, then `linked-versions`
combines the crate updates into one release pull request. The client package
skips its own changelog so the repository keeps one `CHANGELOG.md`. With
`include-component-in-tag: false`, the shared release keeps the existing
`vX.Y.Z` tag convention. See the [Cargo workspace plugin](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md#cargo-workspace), [linked versions plugin](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md#linked-versions), and [Cargo manifest updater](https://github.com/googleapis/release-please/blob/main/src/updaters/rust/cargo-toml.ts) documentation.

Review each generated release pull request. Both `Cargo.toml` package
versions, the `baffle-client` dependency version in the root manifest,
`.release-please-manifest.json`, and both local package entries in `Cargo.lock`
must match. The `Format, lint, and test` required check runs on regular pull
requests and verifies the Release Please package and plugin configuration.
The generated release pull request is checked separately as described below.

Crate names are allocated on a first-come basis. Before the first release,
confirm that `baffle-client` and `baffle-proxy` are available and that the
crates.io account which owns them is the intended release account. The
publication job checks both crate names before it uploads either package. If a
name belongs to another project, the job stops and reports the conflict. It
does not choose another crate name.

The GitHub repository owner `dstoc` must own both crates on crates.io. Add
that user as an owner before enabling automated publication if another account
made the first publish. The workflow checks the recorded repository URL and
owner list before it skips an existing version or publishes a new one. The
`CARGO_REGISTRY_TOKEN` repository secret must belong to an account with
permission to publish both crates. The workflow reads it only in the trusted
publishing job. Its scope must allow Cargo to publish both crates and read
their owner lists. If the token is missing, expired, scoped incorrectly, or
does not have owner permission, the job stops with the registry error. No PAT,
GitHub Environment, or GitHub App token is required. See the Cargo
[publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html)
for name allocation and owner management.

Before a release, run these package checks from the repository root:

```sh
cargo metadata --locked --format-version 1
python3 -m unittest scripts.test_release_please_manifests scripts.test_publish_crates
cargo package --list --locked --package baffle-client
cargo package --list --locked --package baffle-proxy
cargo publish --dry-run --locked --package baffle-client
```

The client dry run packages, extracts, and builds the client crate without
publishing it. `baffle-proxy` can be inspected before its dependency is in the
registry. The publication job runs a full proxy dry run after it confirms the
matching `baffle-client` version is available. It then publishes the proxy.
Never use a real `cargo publish` as a packaging check.

The publishing job runs only when Release Please reports a release from
`main`. It checks out the exact reported tag and commit. It requires a `vX.Y.Z`
tag, a matching non-draft GitHub Release, two matching Cargo package versions,
and the matching versioned `baffle-client` dependency. It rejects prereleases.
The release job has `contents: read` permission. Only the Release Please job
has permission to create tags and releases. Normal pull requests and runs that
do not create a release cannot read the crates.io secret.

The workflow checks the registry before publishing. It skips an exact version
only when the crate name, repository URL, and expected owner match. It fails
when a crate name or version has an unexpected identity. The client publishes
first. The workflow waits for that exact version to appear in the registry
index before it validates and publishes the proxy. If the client publishes but
the proxy fails, the run reports that partial state. Choose **Re-run failed
jobs** in the same Actions run to resume. The publishing job confirms the
existing client version and continues with the proxy. Do not choose **Re-run
all jobs** because Release Please may no longer report that it created the
existing release. Crates.io versions are immutable and are never overwritten.
A publication which already succeeded is reported as such on a rerun.

The `Format, lint, and test` required check remains in place. It validates
regular pull requests and is not replaced by the publishing job. Linux binary
assets also remain outside crates.io publication and must be dispatched
manually as described below.

To test the workflow without creating a release, run the `scripts` Python unit
tests and the package checks above. The publication tests use a fake registry
and never upload a crate. Do not dispatch Release Please to test publishing;
that could create a real tag and GitHub Release.

## Validate generated release pull requests

GitHub does not start ordinary workflow runs for most events caused by
`GITHUB_TOKEN`. Release Please uses that token to create or update its pull
request, so the pull request does not start the Rust CI workflow.

When Release Please creates or updates a pull request, the `Release Please`
workflow checks out the generated head branch and runs
`cargo metadata --locked --format-version 1` against it. It then runs the
Release Please regression tests on that branch. Cargo metadata checks that the
candidate resolves without changing `Cargo.lock`. The regression tests check
that both crate versions, the `baffle-client` dependency version, the manifest
entries, and the lockfile entries stay in sync. Before merging, confirm that
the `Release Please` workflow run completed both checks successfully for the
latest candidate commit. Release Please creates the candidate with
`GITHUB_TOKEN`, so GitHub may not start the normal CI workflow for that pull
request. When a release is created, the same workflow calls the full Rust CI
workflow on the release commit and waits for the required `Format, lint, and
test` check before it starts publishing. Regular pull requests continue to run
the same required CI check.

A tag created with `GITHUB_TOKEN` does not trigger another workflow run. The
same Release Please run handles crates.io publication. Use the manual Linux
release workflow described below after the Release Please pull request is
merged and the crates.io run succeeds.

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
