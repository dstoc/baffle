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

## First release and safe local packaging check

The repository currently has no version tags. Both Cargo packages are at
`0.1.0`, so `.release-please-manifest.json` records `0.1.0` as the current
workspace version. On its first run, Release Please can inspect the existing
commit history because there is no earlier release tag. Review the first
generated release pull request's proposed version and changelog before merging
it; merging that pull request creates the first release tag.

To verify the packaging steps without publishing a release, run the packaging
script locally against the current Cargo version. This creates only local files
under `dist/`:

```sh
./scripts/package-release.sh v0.1.0
tar -tzf dist/baffle-proxy-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
(cd dist && sha256sum -c SHA256SUMS)
```

This safe check exercises the Cargo version and MIT license gates, Linux build,
archive contents, and checksum generation. It does not simulate a GitHub tag or
upload assets.
