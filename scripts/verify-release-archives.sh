#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 vX.Y.Z <archive-directory>" >&2
  exit 2
fi

release_tag="$1"
dist_dir="$2"
if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Expected a stable vX.Y.Z release tag; got '$release_tag'." >&2
  exit 1
fi

linux="baffle-proxy-${release_tag}-x86_64-unknown-linux-gnu.tar.gz"
macos="baffle-proxy-${release_tag}-aarch64-apple-darwin.tar.gz"
shopt -s nullglob
archives=("$dist_dir"/*.tar.gz)
if [[ ${#archives[@]} -ne 2 || ! -f "$dist_dir/$linux" || ! -f "$dist_dir/$macos" ]]; then
  echo "Expected exactly '$linux' and '$macos' in '$dist_dir'." >&2
  exit 1
fi

for archive in "$linux" "$macos"; do
  tar -tzf "$dist_dir/$archive" | grep -Fx './baffle' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx './LICENSE' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx './share/doc/baffle/README.md' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx './share/doc/baffle/docs/releasing.md' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx './share/doc/baffle/examples/daemon.toml' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx \
    './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx \
    './share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt' >/dev/null
done

temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT
mkdir -p "$temporary_dir/linux" "$temporary_dir/macos"
tar -xzf "$dist_dir/$linux" -C "$temporary_dir/linux" ./baffle
tar -xzf "$dist_dir/$macos" -C "$temporary_dir/macos" ./baffle

linux_file="$(file "$temporary_dir/linux/baffle")"
macos_file="$(file "$temporary_dir/macos/baffle")"
if [[ "$linux_file" != *"ELF 64-bit"* || "$linux_file" != *"x86-64"* ]]; then
  echo "Wrong Linux executable architecture: $linux_file" >&2
  exit 1
fi
if [[ "$macos_file" != *"Mach-O 64-bit"* || "$macos_file" != *"arm64"* ]]; then
  echo "Wrong Apple Silicon executable architecture: $macos_file" >&2
  exit 1
fi

(
  cd "$dist_dir"
  sha256sum "$linux" "$macos" > SHA256SUMS
  sha256sum --check SHA256SUMS
)

echo "Verified $linux, $macos, and the combined SHA256SUMS."
