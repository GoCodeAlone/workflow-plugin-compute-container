#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export LANG=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "$repo_root"

out_dir=".release/managed-runtime-bundles"
bundle_id="managed-containerd-linux-amd64"
release_tag="v2.3.1"
source_base_url="https://github.com/containerd/nerdctl/releases/download/${release_tag}"
artifact_name="nerdctl-full-2.3.1-linux-amd64.tar.gz"
artifact_digest="7a0d8efcf55b10b57d831541266adb9c6ec3d55b44ec041c95f6eb994d1faab9"
checksum_digest="8a0586ff11d4d5a5d19d59494a10af8c6d41dd95ca72ff347f62d5288bc5131a"
signature_digest="f87400e0923e22eab251328bd210bb9e8d3bba2b58dbbb84699622474344d68c"
trust_root_name="ChengyuZhu6.gpg"
trust_root_url="https://github.com/ChengyuZhu6.gpg"
trust_root_digest="812ecad48a498fe3fbda46805da3fb2e98328531e3aac3e171a63c9daa1d9206"
manifest="${out_dir}/${bundle_id}.source.json"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$1" | awk '{print $1}'
}

require_digest() {
  local file="$1"
  local want="$2"
  local got
  got="$(sha256_file "$file")"
  if [ "$got" != "$want" ]; then
    printf 'managed runtime bundle digest mismatch for %s: got %s want %s\n' "$file" "$got" "$want" >&2
    exit 1
  fi
}

rm -rf "$out_dir"
mkdir -p "$out_dir"
curl -fsSL -o "${out_dir}/SHA256SUMS" "${source_base_url}/SHA256SUMS"
curl -fsSL -o "${out_dir}/SHA256SUMS.asc" "${source_base_url}/SHA256SUMS.asc"
curl -fsSL -o "${out_dir}/${trust_root_name}" "${trust_root_url}"
require_digest "${out_dir}/SHA256SUMS" "$checksum_digest"
require_digest "${out_dir}/SHA256SUMS.asc" "$signature_digest"
require_digest "${out_dir}/${trust_root_name}" "$trust_root_digest"
if ! grep -F "${artifact_digest}  ${artifact_name}" "${out_dir}/SHA256SUMS" >/dev/null; then
  printf 'managed runtime artifact %s with digest %s not found in SHA256SUMS\n' "$artifact_name" "$artifact_digest" >&2
  exit 1
fi

cat > "$manifest" <<EOF
{
  "bundle_id": "${bundle_id}",
  "source_url": "${source_base_url}/${artifact_name}",
  "artifact_name": "${artifact_name}",
  "artifact_digest": "sha256:${artifact_digest}",
  "checksum_url": "${source_base_url}/SHA256SUMS",
  "checksum_digest": "sha256:${checksum_digest}",
  "signature_url": "${source_base_url}/SHA256SUMS.asc",
  "signature_digest": "sha256:${signature_digest}",
  "trust_root_url": "${trust_root_url}",
  "trust_root_name": "${trust_root_name}",
  "trust_root_digest": "sha256:${trust_root_digest}"
}
EOF
sha256_file "$manifest" > "${manifest}.sha256"
cp managed-runtime-bundles.json "${out_dir}/managed-runtime-bundles.json"
