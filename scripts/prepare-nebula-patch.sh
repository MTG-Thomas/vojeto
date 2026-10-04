#!/bin/sh
# Create a private patched dependency copy and alternate modfile. Never edit GOMODCACHE.
set -eu
[ "$#" -eq 2 ] || { echo 'Expected destination and alternate modfile' >&2; exit 1; }
destination=$1
alternate=$2
case "$destination" in /*) ;; *) echo "Expected absolute dependency destination" >&2; exit 1;; esac
case "$alternate" in /*.mod) ;; *) echo "Expected absolute alternate modfile" >&2; exit 1;; esac
[ ! -e "$destination" ] && [ ! -L "$destination" ] && [ ! -e "$alternate" ] && [ ! -L "$alternate" ] && [ ! -e "${alternate%.mod}.sum" ] && [ ! -L "${alternate%.mod}.sum" ] || { echo 'Patch destination already exists' >&2; exit 1; }
[ "$(go list -m -f '{{.Version}}' github.com/slackhq/nebula)" = 'v1.11.2' ] || { echo 'Unreviewed Nebula version' >&2; exit 1; }
go mod download github.com/slackhq/nebula
go mod verify
original=$(go list -m -f '{{.Dir}}' github.com/slackhq/nebula)
printf '%s  %s\n' 'afd89918eea7af4b41a12c16908de18f52370596cbec556e5832b99220f610f1' "$original/handshake_manager.go" | sha256sum -c -
printf '%s  %s\n' 'e87cf44c0da58696dde449c5295cee91fee2cd2d2459ffeb5dae2f14e34f86e3' 'patches/nebula-v1.11.2-packet-cache.patch' | sha256sum -c -
cp -a "$original" "$destination"
chmod -R u+w "$destination"
patch_file=$(pwd)/patches/nebula-v1.11.2-packet-cache.patch
(cd "$destination" && git apply --check "$patch_file" && git apply "$patch_file")
cp go.mod "$alternate"
cp go.sum "${alternate%.mod}.sum"
go mod edit -modfile="$alternate" -replace="github.com/slackhq/nebula=$destination"
