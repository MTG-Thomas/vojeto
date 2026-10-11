"""Verify private OCI signature and release statement before consumer admission."""
import argparse
import base64
import json
import re
import subprocess

from release_policy import destination, require


def statement(envelopes, image, repository, source, kind):
    digest = image.rsplit("@sha256:", 1)[1]
    workflow = f"{repository}/.github/workflows/publish-{kind}.yml@refs/heads/main"
    identity = "https://github.com/" + workflow
    predicate_type = f"https://github.com/{repository}/attestations/release/v1"
    admitted = 0
    for envelope in envelopes:
        require(envelope.get("payloadType") == "application/vnd.in-toto+json")
        payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
        require(payload.get("_type") in ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"))
        require(payload.get("predicateType") == predicate_type)
        subjects = payload.get("subject", [])
        require(len(subjects) == 1 and subjects[0].get("digest", {}).get("sha256") == digest)
        p = payload.get("predicate", {})
        require(p.get("schemaVersion") == 1 and p.get("repository") == repository
                and p.get("sourceCommit") == source and p.get("workflow") == workflow
                and p.get("platform") == "linux/amd64" and p.get("image") == image
                and p.get("environment") == "vojeto-release"
                and p.get("signingIssuer") == "https://token.actions.githubusercontent.com"
                and p.get("signingIdentity") == identity
                and p.get("target") == {"client": "release", "launcher": "launcher-release"}[kind]
                and re.fullmatch(r"[1-9][0-9]*", str(p.get("runID", ""))) is not None
                and re.fullmatch(r"[1-9][0-9]*", str(p.get("runAttempt", ""))) is not None)
        admitted += 1
    require(admitted > 0)


def verify(image, repository, source, kind):
    require(re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository) is not None)
    require(re.fullmatch(r"ghcr\.io/[a-z0-9-]+/[a-z0-9._-]+@sha256:[0-9a-f]{64}", image) is not None)
    destination(image.split("@", 1)[0], repository)
    require(re.fullmatch(r"[0-9a-f]{40}", source) is not None)
    workflow = f"{repository}/.github/workflows/publish-{kind}.yml@refs/heads/main"
    trust = ["--certificate-identity", "https://github.com/" + workflow,
             "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
             "--certificate-github-workflow-sha", source,
             "--certificate-github-workflow-trigger", "workflow_dispatch"]
    subprocess.run(["cosign", "verify", *trust, "--annotations", "git_sha=" + source,
                    "--annotations", "source_repo=" + repository, image],
                   check=True, capture_output=True, timeout=180)
    result = subprocess.run(["cosign", "verify-attestation", *trust, "--type",
                             f"https://github.com/{repository}/attestations/release/v1", image],
                            check=True, capture_output=True, text=True, timeout=180)
    require(len(result.stdout) <= 4 << 20)
    # Cosign emits one verified DSSE JSON envelope per line. Accept array output
    # as well, but never parse unverified registry data as trust evidence.
    try:
        parsed = json.loads(result.stdout)
        envelopes = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        envelopes = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    statement(envelopes, image, repository, source, kind)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--kind", choices=("client", "launcher"), default="client")
    args = parser.parse_args()
    try:
        verify(args.image, args.repository, args.source, args.kind)
    except (ValueError, KeyError, TypeError, AttributeError, OSError, subprocess.SubprocessError):
        raise SystemExit("Release refused: digest, signature, identity or source evidence did not verify.") from None
    print("Release digest, signing identity and source statement verified.")


if __name__ == "__main__":
    main()
