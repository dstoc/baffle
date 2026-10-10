#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <Linux ELF executable>" >&2
  exit 2
fi

binary="$1"
if ! readelf -l "$binary" | grep -Fq 'Requesting program interpreter'; then
  echo "Executable is not dynamically linked: $binary" >&2
  exit 1
fi

glibc_versions="$(readelf --version-info --wide "$binary" \
  | grep -oE 'Name: GLIBC_[0-9]+(\.[0-9]+)+' \
  | sed 's/^Name: //' \
  | sort -Vu || true)"
if [[ -z "$glibc_versions" ]]; then
  echo "Could not find GNU C Library symbol requirements in '$binary'." >&2
  exit 1
fi

tail -n 1 <<< "$glibc_versions"
