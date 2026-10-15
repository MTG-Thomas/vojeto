#!/usr/bin/env bash
# Invoked only by the protected, exact-source publisher. Never run as a deploy.
set -euo pipefail
test "$GITHUB_REF" = refs/heads/main
test "$EXPECTED_SHA" = "$GITHUB_SHA"
case "$RELEASE_TARGET" in release|launcher-release) ;; *) exit 1 ;; esac
python3 scripts/release_policy.py --image "$RELEASE_IMAGE" --expected-sha "$EXPECTED_SHA" --visibility "$RELEASE_VISIBILITY"
printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT
docker build --target "$RELEASE_TARGET" \
  --label "org.opencontainers.image.source=$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
  --label "org.opencontainers.image.revision=$GITHUB_SHA" \
  --tag "$RELEASE_IMAGE:$GITHUB_SHA" .
docker push "$RELEASE_IMAGE:$GITHUB_SHA"
reference="$(docker inspect --format '{{index .RepoDigests 0}}' "$RELEASE_IMAGE:$GITHUB_SHA")"
REFERENCE="$reference" python3 - <<'PY'
import os,re
assert re.fullmatch(re.escape(os.environ['RELEASE_IMAGE'])+r'@sha256:[0-9a-f]{64}',os.environ['REFERENCE'])
PY
cosign sign --yes --bundle "$RUNNER_TEMP/vojeto-image-signature.sigstore.json" \
  --annotations "git_sha=$GITHUB_SHA" --annotations "source_repo=$GITHUB_REPOSITORY" "$reference"
REFERENCE="$reference" python3 - <<'PY'
import json,os,pathlib
e=os.environ
manifest={"schemaVersion":1,"repository":e["GITHUB_REPOSITORY"],"sourceCommit":e["GITHUB_SHA"],
          "workflow":e["GITHUB_WORKFLOW_REF"],"runID":e["GITHUB_RUN_ID"],"runAttempt":e["GITHUB_RUN_ATTEMPT"],
          "platform":"linux/amd64","image":e["REFERENCE"],"target":e["RELEASE_TARGET"],
          "environment":"vojeto-release","signingIssuer":"https://token.actions.githubusercontent.com",
          "signingIdentity":e["GITHUB_SERVER_URL"]+"/"+e["GITHUB_WORKFLOW_REF"]}
pathlib.Path(e["RUNNER_TEMP"],"vojeto-release-manifest.json").write_text(json.dumps(manifest,sort_keys=True)+"\n")
PY
predicate="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/attestations/release/v1"
cosign attest --yes --bundle "$RUNNER_TEMP/vojeto-manifest-signature.sigstore.json" \
  --type "$predicate" --predicate "$RUNNER_TEMP/vojeto-release-manifest.json" "$reference"
# Verify before reporting a qualified release; no public Actions binary upload.
case "$RELEASE_TARGET" in release) release_kind=client ;; launcher-release) release_kind=launcher ;; esac
python3 scripts/verify_release.py --image "$reference" --repository "$GITHUB_REPOSITORY" \
  --source "$GITHUB_SHA" --kind "$release_kind"
printf '%s\n' "$reference" >> "$GITHUB_STEP_SUMMARY"
