#!/bin/sh
# Keep the pinned dependency and retransmission regression in a private copy.
set -eu
[ "$#" -eq 2 ] || { echo 'Expected destination and existing alternate modfile' >&2; exit 1; }
destination=$1
alternate=$2
case "$destination" in /*) ;; *) exit 1;; esac
case "$alternate" in /*.mod) ;; *) exit 1;; esac
[ ! -e "$destination" ] && [ ! -L "$destination" ] && [ -f "$alternate" ] && [ ! -L "$alternate" ] || { echo 'Unsafe patch destination or alternate modfile' >&2; exit 1; }
[ "$(go list -m -f '{{.Version}}' gvisor.dev/gvisor)" = 'v0.0.0-20240423190808-9d7a357edefe' ] || { echo 'Unreviewed gVisor version' >&2; exit 1; }
go mod download gvisor.dev/gvisor
original=$(go list -m -f '{{.Dir}}' gvisor.dev/gvisor)
printf '%s  %s\n' '3fe4c04b3912c72bfd1a4793c3f380cfc51efd5a75c16eb194fc482d7ba9309e' "$original/pkg/tcpip/transport/tcp/snd.go" | sha256sum -c -
printf '%s  %s\n' '16f372a233e98c779f685ec216d74cae801efc0198b6b640adba720bb68d9fcd' patches/gvisor-9d7a357edefe-retransmission-timer.patch | sha256sum -c -
cp -a "$original" "$destination"
chmod -R u+w "$destination"
patch_file=$(pwd)/patches/gvisor-9d7a357edefe-retransmission-timer.patch
(cd "$destination" && git apply --check "$patch_file" && git apply "$patch_file")
printf '%s  %s\n' '95ed275a465334538bcf279c5318da0cc16e55857896a6b40b038e13c7301cd5' patches/gvisor-9d7a357edefe-small-window.patch | sha256sum -c -
window_patch=$(pwd)/patches/gvisor-9d7a357edefe-small-window.patch
(cd "$destination" && git apply --check "$window_patch" && git apply "$window_patch")
go mod edit -modfile="$alternate" -replace="gvisor.dev/gvisor=$destination"
