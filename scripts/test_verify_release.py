import base64
import json
import subprocess
import unittest
from unittest.mock import patch

import release_policy
import verify_release


class VerifyReleaseTests(unittest.TestCase):
    repo = "fixture-owner/repo"
    source = "a" * 40
    image = "ghcr.io/fixture-owner/runtime@sha256:" + "b" * 64

    def payload(self):
        workflow = self.repo + "/.github/workflows/publish-client.yml@refs/heads/main"
        return {"_type": "https://in-toto.io/Statement/v0.1",
                "predicateType": "https://github.com/" + self.repo + "/attestations/release/v1",
                "subject": [{"name": "fixture-runtime", "digest": {"sha256": "b" * 64}}],
                "predicate": {"schemaVersion": 1, "repository": self.repo, "sourceCommit": self.source,
                              "workflow": workflow, "platform": "linux/amd64", "image": self.image,
                              "target": "release", "environment": "vojeto-release", "runID": "123",
                              "runAttempt": "1", "signingIssuer": "https://token.actions.githubusercontent.com",
                              "signingIdentity": "https://github.com/" + workflow}}

    def envelope(self, payload):
        return {"payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(json.dumps(payload).encode()).decode()}

    def test_exact_verified_release_statement(self):
        verify_release.statement([self.envelope(self.payload())], self.image, self.repo, self.source, "client")

    def test_statement_rejects_changed_digest_source_issuer_workflow_target_and_empty_evidence(self):
        for field, value in [("sourceCommit", "c" * 40), ("workflow", "foreign"), ("image", "foreign"),
                             ("signingIssuer", "https://foreign.example"), ("target", "launcher-release"),
                             ("runAttempt", "0"), ("environment", "unprotected"), ("platform", "linux/arm64")]:
            p = self.payload(); p["predicate"][field] = value
            with self.assertRaises(release_policy.Rejected):
                verify_release.statement([self.envelope(p)], self.image, self.repo, self.source, "client")
        p = self.payload(); p["subject"][0]["digest"]["sha256"] = "c" * 64
        with self.assertRaises(release_policy.Rejected):
            verify_release.statement([self.envelope(p)], self.image, self.repo, self.source, "client")
        with self.assertRaises(release_policy.Rejected):
            verify_release.statement([], self.image, self.repo, self.source, "client")

    def test_untrusted_signature_never_reaches_statement_parser(self):
        with patch.object(verify_release.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cosign")) as run, \
                patch.object(verify_release, "statement") as statement:
            with self.assertRaises(subprocess.CalledProcessError):
                verify_release.verify(self.image, self.repo, self.source, "client")
            statement.assert_not_called()
            self.assertEqual(run.call_count, 1)
            args = run.call_args.args[0]
            self.assertIn("--certificate-github-workflow-sha", args)
            self.assertNotIn("--insecure-ignore-tlog", args)

    def test_attestation_parser_runs_only_after_both_crypto_checks(self):
        envelope = self.envelope(self.payload())
        with patch.object(verify_release.subprocess, "run", side_effect=[
            subprocess.CompletedProcess("cosign", 0, ""),
            subprocess.CompletedProcess("cosign", 0, json.dumps(envelope))]) as run:
            verify_release.verify(self.image, self.repo, self.source, "client")
            self.assertEqual(run.call_count, 2)
        with patch.object(verify_release.subprocess, "run") as run:
            with self.assertRaises(release_policy.Rejected):
                verify_release.verify(self.image.replace("fixture-owner", "foreign"), self.repo, self.source, "client")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
