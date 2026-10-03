#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
revision=$(git rev-parse HEAD)
[[ -z $(git status --porcelain --untracked-files=no) ]] || {
    echo 'Refusing to label a dirty tracked checkout with a clean commit ID.' >&2
    exit 1
}
bundle_name="cardwire-linux-x86_64-${revision}"
bundle_tmp=$(mktemp -d)
trap 'rm -r -- "$bundle_tmp"' EXIT
mkdir -p -- "$bundle_tmp/$bundle_name/bin" dist
for binary in cardwired cardwire cardwire-gui; do
    install -m755 "target/release/$binary" "$bundle_tmp/$bundle_name/bin/$binary"
done
cp -a assets "$bundle_tmp/$bundle_name/"
cp LICENSE Cargo.lock FORK.md "$bundle_tmp/$bundle_name/"
git archive --format=tar.gz --output="$bundle_tmp/$bundle_name/source.tar.gz" HEAD
{
    printf 'Source commit: %s\n' "$revision"
    printf 'Source repository: https://github.com/keefeere/cardwire\n'
    printf 'Built: %s\n' "$(date -u +%FT%TZ)"
    rustc +1.95.0 --version
    rustc +nightly-2026-08-12 --version
    bpf-linker --version
    printf 'Build: cargo +1.95.0 build --locked --release --config profile.release.lto=false\n'
    printf 'No install or restart has been performed. See FORK.md.\n'
} > "$bundle_tmp/$bundle_name/BUILD.txt"
(
    cd -- "$bundle_tmp/$bundle_name"
    sha256sum bin/* Cargo.lock source.tar.gz > SHA256SUMS
)
tar -C "$bundle_tmp" -czf "dist/$bundle_name.tar.gz" "$bundle_name"
(
    cd dist
    sha256sum "$bundle_name.tar.gz" > "$bundle_name.tar.gz.sha256"
)
