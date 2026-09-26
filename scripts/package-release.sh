#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 vX.Y.Z [output-directory]" >&2
  exit 2
fi

release_tag="$1"
output_dir="${2:-dist}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Expected a stable vX.Y.Z release tag; got '$release_tag'." >&2
  exit 1
fi

version="${release_tag#v}"
metadata="$(cargo metadata --no-deps --format-version 1)"
package_version="$(jq -r '.packages[] | select(.name == "baffle-proxy") | .version' <<< "$metadata")"
package_license="$(jq -r '.packages[] | select(.name == "baffle-proxy") | .license // empty' <<< "$metadata")"

if [[ "$package_version" != "$version" ]]; then
  echo "Tag '$release_tag' does not match baffle-proxy Cargo version '$package_version'." >&2
  exit 1
fi
if [[ ! -s LICENSE || "$package_license" != "MIT" ]]; then
  echo "Release packaging requires a non-empty LICENSE and Cargo license = MIT." >&2
  exit 1
fi

cargo build --locked --release --package baffle-proxy --bin baffle
binary_version="$(./target/release/baffle --version)"
if [[ "$binary_version" != "baffle $version" ]]; then
  echo "Built binary reports '$binary_version'; expected 'baffle $version'." >&2
  exit 1
fi

target="x86_64-unknown-linux-gnu"
asset="baffle-proxy-${release_tag}-${target}.tar.gz"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/share/doc/baffle"
install -m 0755 target/release/baffle "$stage/baffle"
install -m 0644 LICENSE "$stage/LICENSE"
install -m 0644 README.md "$stage/share/doc/baffle/README.md"
python3 scripts/generate-third-party-notices.py \
  --output "$stage/share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt"
install -D -m 0644 licenses/webpki-root-certs-CDLA-Permissive-2.0.txt \
  "$stage/share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt"
cp -R docs "$stage/share/doc/baffle/docs"
cp -R examples "$stage/share/doc/baffle/examples"
mkdir -p "$output_dir"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$stage" -cf - . | gzip -n > "$output_dir/$asset"

tar -tzf "$output_dir/$asset" | grep -Fx './LICENSE'
tar -tzf "$output_dir/$asset" | grep -Fx \
  './share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt'
tar -tzf "$output_dir/$asset" | grep -Fx \
  './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt'
tar -xOf "$output_dir/$asset" './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt' | \
  grep -F 'Package: tokio '
tar -xOf "$output_dir/$asset" './share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt' | \
  grep -F 'Package: rama-core '
(cd "$output_dir" && sha256sum "$asset" > SHA256SUMS)

echo "Prepared $output_dir/$asset and $output_dir/SHA256SUMS. No GitHub release was changed."
