#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 vX.Y.Z <target-triple> [output-directory]" >&2
  exit 2
fi

release_tag="$1"
target="$2"
output_dir="${3:-dist}"
tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${BAFFLE_SOURCE_DIR:-$tool_root}"
repo_root="$(cd "$source_dir" && pwd)"
cd "$repo_root"

if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Expected a stable vX.Y.Z release tag; got '$release_tag'." >&2
  exit 1
fi

case "$target" in
  x86_64-unknown-linux-gnu)
    if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
      echo "Target $target must be built on Linux x86-64." >&2
      exit 1
    fi
    ;;
  aarch64-apple-darwin)
    if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
      echo "Target $target must be built on Apple Silicon macOS." >&2
      exit 1
    fi
    ;;
  *)
    echo "Unsupported release target '$target'." >&2
    exit 1
    ;;
esac

version="${release_tag#v}"
metadata="$(cargo metadata --locked --no-deps --format-version 1)"
package_version="$(jq -r '.packages[] | select(.name == "baffle-proxy") | .version' <<< "$metadata")"
package_license="$(jq -r '.packages[] | select(.name == "baffle-proxy") | .license // empty' <<< "$metadata")"

if [[ "$package_version" != "$version" ]]; then
  echo "Tag '$release_tag' does not match baffle-proxy Cargo version '$package_version'." >&2
  exit 1
fi
if [[ ! -s LICENSE || "$package_license" != MIT ]]; then
  echo "Release packaging requires a non-empty LICENSE and Cargo license = MIT." >&2
  exit 1
fi

cargo build --locked --release --target "$target" --package baffle-proxy --bin baffle
binary="target/$target/release/baffle"
binary_version="$("$binary" --version)"
if [[ "$binary_version" != "baffle $version" ]]; then
  echo "Built binary reports '$binary_version'; expected 'baffle $version'." >&2
  exit 1
fi

file_description="$(file "$binary")"
case "$target" in
  x86_64-unknown-linux-gnu)
    if [[ "$file_description" != *"ELF 64-bit"* || "$file_description" != *"x86-64"* ]]; then
      echo "Built executable does not have the expected Linux x86-64 architecture: $file_description" >&2
      exit 1
    fi
    ;;
  aarch64-apple-darwin)
    if [[ "$file_description" != *"Mach-O 64-bit"* || "$file_description" != *"arm64"* ]] || \
       ! lipo -archs "$binary" | tr ' ' '\n' | grep -Fxq arm64; then
      echo "Built executable does not have the expected Apple Silicon architecture: $file_description" >&2
      exit 1
    fi
    ;;
esac

asset="baffle-proxy-${release_tag}-${target}.tar.gz"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/share/doc/baffle/licenses"
install -m 0755 "$binary" "$stage/baffle"
install -m 0644 LICENSE "$stage/LICENSE"
install -m 0644 README.md "$stage/share/doc/baffle/README.md"
python3 "$tool_root/scripts/generate-third-party-notices.py" \
  --source-dir "$repo_root" \
  --target "$target" \
  --output "$stage/share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt"
install -m 0644 licenses/webpki-root-certs-CDLA-Permissive-2.0.txt \
  "$stage/share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt"
cp -R docs "$stage/share/doc/baffle/docs"
cp -R examples "$stage/share/doc/baffle/examples"
mkdir -p "$output_dir"
python3 "$tool_root/scripts/create-release-archive.py" "$stage" "$output_dir/$asset"

tar -tzf "$output_dir/$asset" | grep -Fx './LICENSE'
tar -tzf "$output_dir/$asset" | grep -Fx './share/doc/baffle/README.md'
tar -tzf "$output_dir/$asset" | grep -Fx './share/doc/baffle/docs/releasing.md'
tar -tzf "$output_dir/$asset" | grep -Fx './share/doc/baffle/examples/daemon.toml'
tar -tzf "$output_dir/$asset" | grep -Fx \
  './share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt'
tar -tzf "$output_dir/$asset" | grep -Fx \
  './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt'
tar -xOf "$output_dir/$asset" './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt' | \
  grep -F 'Package: tokio '
tar -xOf "$output_dir/$asset" './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt' | \
  grep -F 'Package: rama-core '

echo "Prepared $output_dir/$asset for $target. No GitHub release was changed."
