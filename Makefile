.PHONY: test build build-peer build-launcher
# Patch in an isolated temporary directory; never mutate the module cache.
test:
	@set -eu; task_dir=$$(mktemp -d); trap 'rm -rf "$$task_dir"' EXIT; scripts/prepare-nebula-patch.sh "$$task_dir/nebula" "$$task_dir/vojeto.mod"; go test -modfile="$$task_dir/vojeto.mod" -race -run "^TestVojetoTailProbe" -count=100 gvisor.dev/gvisor/pkg/tcpip/transport/tcp; CGO_ENABLED=0 go build -modfile="$$task_dir/vojeto.mod" -o "$$task_dir/vojeto-peer" ./cmd/vojeto-peer; chmod 0555 "$$task_dir/vojeto-peer"; VOJETO_PEER_BINARY="$$task_dir/vojeto-peer" go test -modfile="$$task_dir/vojeto.mod" -race ./...
build:
	@set -eu; task_dir=$$(mktemp -d); trap 'rm -rf "$$task_dir"' EXIT; scripts/prepare-nebula-patch.sh "$$task_dir/nebula" "$$task_dir/vojeto.mod"; CGO_ENABLED=0 go build -modfile="$$task_dir/vojeto.mod" -trimpath -o vojeto ./cmd/vojeto

build-peer:
	@set -eu; task_dir=$$(mktemp -d); trap 'rm -rf "$$task_dir"' EXIT; scripts/prepare-nebula-patch.sh "$$task_dir/nebula" "$$task_dir/vojeto.mod"; CGO_ENABLED=0 go build -modfile="$$task_dir/vojeto.mod" -trimpath -o vojeto-peer ./cmd/vojeto-peer

build-launcher:
	@set -eu; task_dir=$$(mktemp -d); trap 'rm -rf "$$task_dir"' EXIT; scripts/prepare-nebula-patch.sh "$$task_dir/nebula" "$$task_dir/vojeto.mod"; CGO_ENABLED=0 go build -modfile="$$task_dir/vojeto.mod" -trimpath -o vojeto-launcher ./cmd/vojeto-launcher
