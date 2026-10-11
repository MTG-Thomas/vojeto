#!/usr/bin/env bash
# Synthetic offline keys are destroyed on exit. Production requires keyless,
# transparency-verified OCI evidence and never ignores the transparency log.
set -euo pipefail
umask 077
fixture_dir="$(mktemp -d /tmp/vojeto-signature-test.XXXXXXXX)"
trap 'rm -rf -- "$fixture_dir"' EXIT
cd "$fixture_dir"
export COSIGN_PASSWORD=''
cosign generate-key-pair --output-key-prefix synthetic > generate.log 2>&1
printf '%s\n' '{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json"}' > offline-config.json
printf '%s\n' 'synthetic release content' > artifact
cosign sign-blob --yes --key synthetic.key --signing-config offline-config.json \
  --bundle signed.json artifact > sign.log 2>&1
cosign verify-blob --key synthetic.pub --bundle signed.json --insecure-ignore-tlog \
  artifact > verify.log 2>&1
printf '%s\n' 'tampered content' >> artifact
if cosign verify-blob --key synthetic.pub --bundle signed.json --insecure-ignore-tlog \
  artifact > tampered.log 2>&1; then
  echo 'Tampered artifact was accepted' >&2
  exit 1
fi
printf '%s\n' 'Synthetic signature verified; tampered content rejected.'
