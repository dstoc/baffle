#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 vX.Y.Z <archive-directory>" >&2
  exit 2
fi

release_tag="$1"
dist_dir="$2"
tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Expected a stable vX.Y.Z release tag; got '$release_tag'." >&2
  exit 1
fi

linux="baffle-proxy-${release_tag}-x86_64-unknown-linux-gnu.tar.gz"
linux_arm64="baffle-proxy-${release_tag}-aarch64-unknown-linux-gnu.tar.gz"
macos="baffle-proxy-${release_tag}-aarch64-apple-darwin.tar.gz"
expected_archives=("$linux" "$linux_arm64" "$macos")
shopt -s nullglob
archives=("$dist_dir"/*.tar.gz)
if [[ ${#archives[@]} -ne ${#expected_archives[@]} ]]; then
  echo "Expected exactly ${#expected_archives[@]} release archives in '$dist_dir'." >&2
  exit 1
fi

for archive in "${expected_archives[@]}"; do
  if [[ ! -f "$dist_dir/$archive" ]]; then
    echo "Missing expected release archive '$archive' in '$dist_dir'." >&2
    exit 1
  fi
  tar -tzf "$dist_dir/$archive" | grep -Fx './baffle' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx './LICENSE' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx './share/doc/baffle/README.md' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx './share/doc/baffle/docs/releasing.md' >/dev/null
  while IFS= read -r document || [[ -n "$document" ]]; do
    [[ -n "$document" ]] || continue
    tar -tzf "$dist_dir/$archive" | \
      grep -Fx "./share/doc/baffle/docs/$document" >/dev/null
  done < "$tool_root/release-docs.txt"
  if tar -tzf "$dist_dir/$archive" | \
    grep -E 'share/doc/baffle/docs/(archive/|backend-comparison|runtime-migration|baffle-proposal|benchmark-report)' >/dev/null; then
    echo "Release archive contains a historical design or benchmark document: $archive." >&2
    exit 1
  fi
  tar -tzf "$dist_dir/$archive" | grep -Fx './share/doc/baffle/examples/daemon.toml' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx \
    './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt' >/dev/null
  tar -tzf "$dist_dir/$archive" | grep -Fx \
    './share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt' >/dev/null
done

temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT
mkdir -p "$temporary_dir/linux" "$temporary_dir/linux-arm64" "$temporary_dir/macos"
tar -xzf "$dist_dir/$linux" -C "$temporary_dir/linux" ./baffle
tar -xzf "$dist_dir/$linux_arm64" -C "$temporary_dir/linux-arm64" ./baffle
tar -xzf "$dist_dir/$macos" -C "$temporary_dir/macos" ./baffle

linux_file="$(file "$temporary_dir/linux/baffle")"
linux_arm64_file="$(file "$temporary_dir/linux-arm64/baffle")"
macos_file="$(file "$temporary_dir/macos/baffle")"
if [[ "$linux_file" != *"ELF 64-bit"* || "$linux_file" != *"x86-64"* ]]; then
  echo "Wrong Linux executable architecture: $linux_file" >&2
  exit 1
fi
if [[ "$linux_arm64_file" != *"ELF 64-bit"* || "$linux_arm64_file" != *"ARM aarch64"* ]]; then
  echo "Wrong Linux ARM64 executable architecture: $linux_arm64_file" >&2
  exit 1
fi
glibc_maximum="$("$tool_root/glibc-symbol-requirements.sh" "$temporary_dir/linux-arm64/baffle")"
glibc_record="$(tar -xOf "$dist_dir/$linux_arm64" './share/doc/baffle/GLIBC-ABI.txt')"
if [[ "$glibc_record" != *"Minimum required glibc symbol version: $glibc_maximum"* ]]; then
  echo "Linux ARM64 archive does not report its executable's glibc symbol requirement ($glibc_maximum)." >&2
  exit 1
fi
echo "Linux ARM64 executable dynamically links to glibc; minimum required symbol version: $glibc_maximum."
if [[ "$macos_file" != *"Mach-O 64-bit"* || "$macos_file" != *"arm64"* ]]; then
  echo "Wrong Apple Silicon executable architecture: $macos_file" >&2
  exit 1
fi

(
  cd "$dist_dir"
  sha256sum "${expected_archives[@]}" > SHA256SUMS
  sha256sum --check SHA256SUMS
)

echo "Verified ${#expected_archives[@]} release archives and the combined SHA256SUMS."
