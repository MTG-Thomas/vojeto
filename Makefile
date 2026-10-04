.PHONY: test build
# Patch in an isolated temporary directory; never mutate the module cache.
test:
	@set -eu; task_dir=$$(mktemp -d); trap 'rm -rf "$$task_dir"' EXIT; scripts/prepare-nebula-patch.sh "$$task_dir/nebula" "$$task_dir/vojeto.mod"; go test -modfile="$$task_dir/vojeto.mod" -race ./...
build:
	@set -eu; task_dir=$$(mktemp -d); trap 'rm -rf "$$task_dir"' EXIT; scripts/prepare-nebula-patch.sh "$$task_dir/nebula" "$$task_dir/vojeto.mod"; CGO_ENABLED=0 go build -modfile="$$task_dir/vojeto.mod" -trimpath -o vojeto ./cmd/vojeto
