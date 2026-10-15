import copy
import unittest
from unittest.mock import patch

import release_policy as policy


class ReleasePolicyTests(unittest.TestCase):
    def environment(self):
        return {"name": "vojeto-release", "deployment_branch_policy": {
            "protected_branches": False, "custom_branch_policies": True},
            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": True,
                                  "reviewers": [{"type": "User", "reviewer": {"id": 123}}]}]}

    def branches(self):
        return {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}

    def test_environment_requires_exact_main_without_recurring_human_approval(self):
        environment = self.environment()
        environment["protection_rules"] = [{"type": "branch_policy"}]
        policy.protected_environment(environment, self.branches())
        # GitHub may enforce optional admin-added gates; this read-only guard
        # neither requires nor approves them.
        policy.protected_environment(self.environment(), self.branches())
        for field, value in [("deployment_branch_policy", None), ("name", "unprotected")]:
            changed = copy.deepcopy(environment); changed[field] = value
            with self.assertRaises(policy.Rejected):
                policy.protected_environment(changed, self.branches())
        for branch in [{"name": "*", "type": "branch"}, {"name": "main", "type": "tag"},
                       {"name": "feature", "type": "branch"}]:
            with self.assertRaises(policy.Rejected):
                policy.protected_environment(environment, {"total_count": 1, "branch_policies": [branch]})
        with self.assertRaises(policy.Rejected):
            policy.protected_environment(environment, {"total_count": 2, "branch_policies": [
                {"name": "main", "type": "branch"}, {"name": "*", "type": "branch"}]})

    def test_package_must_be_existing_private_and_owned(self):
        package = {"name": "fixture-runtime", "package_type": "container", "visibility": "private",
                   "owner": {"login": "fixture-owner"}}
        policy.private_package(package, "fixture-runtime", "fixture-owner")
        for change in [{"visibility": "public"}, {"visibility": "internal"}, {"package_type": "npm"},
                       {"name": "foreign"}, {"owner": {"login": "foreign"}}]:
            changed = copy.deepcopy(package); changed.update(change)
            with self.assertRaises(policy.Rejected):
                policy.private_package(changed, "fixture-runtime", "fixture-owner")

    def test_destination_rejects_tags_digests_foreign_owners_and_urls(self):
        self.assertEqual(policy.destination("ghcr.io/fixture-owner/runtime", "fixture-owner/repo"), "runtime")
        for image in ["ghcr.io/other/runtime", "ghcr.io/fixture-owner/runtime:latest",
                      "ghcr.io/fixture-owner/runtime@sha256:abc", "https://ghcr.io/fixture-owner/runtime",
                      "ghcr.io/fixture-owner/namespace/runtime", "ghcr.io/fixture-owner/runtime?secret=x"]:
            with self.assertRaises(policy.Rejected):
                policy.destination(image, "fixture-owner/repo")

    def test_wrong_ref_or_source_never_contacts_provider(self):
        with patch.object(policy, "api") as api:
            for ref, head in [("refs/heads/feature", "a" * 40), ("refs/heads/main", "b" * 40)]:
                with self.assertRaises(policy.Rejected):
                    policy.preflight("fixture-owner/repo", "ghcr.io/fixture-owner/runtime", "a" * 40, head, ref)
            api.assert_not_called()

    def test_preflight_requires_exact_push_ci_and_rejects_existing_source_tags(self):
        repo = "fixture-owner/repo"; sha = "a" * 40
        prefix = "repos/" + repo
        package_path = "users/fixture-owner/packages/container/runtime"
        replies = {
            prefix: {"owner": {"type": "User"}},
            prefix + "/commits/main": {"sha": sha},
            prefix + "/environments/vojeto-release": self.environment(),
            prefix + "/environments/vojeto-release/deployment-branch-policies": self.branches(),
            package_path: {"name": "runtime", "package_type": "container", "visibility": "private",
                           "owner": {"login": "fixture-owner"}},
            prefix + "/commits/" + sha: {"commit": {"verification": {"verified": True}}},
            prefix + "/actions/workflows/validate.yml": {"id": 123, "path": ".github/workflows/validate.yml", "state": "active"},
            prefix + "/actions/workflows/validate.yml/runs?head_sha=" + sha + "&event=push&per_page=100": {
                "workflow_runs": [{"workflow_id": 123, "head_sha": sha, "head_branch": "main", "event": "push",
                                   "status": "completed", "conclusion": "success"}]},
            package_path + "/versions?per_page=100&page=1": [],
        }
        def run(data):
            with patch.object(policy, "api", side_effect=lambda path: copy.deepcopy(data[path])):
                policy.preflight(repo, "ghcr.io/fixture-owner/runtime", sha, sha, "refs/heads/main")
        run(replies)
        stale = copy.deepcopy(replies)
        stale[prefix + "/commits/main"] = {"sha": "b" * 40}
        with self.assertRaises(policy.Rejected):
            run(stale)
        changed = copy.deepcopy(replies)
        changed[package_path + "/versions?per_page=100&page=1"] = [{"metadata": {"container": {"tags": [sha]}}}]
        with self.assertRaises(policy.Rejected):
            run(changed)
        run_path = prefix + "/actions/workflows/validate.yml/runs?head_sha=" + sha + "&event=push&per_page=100"
        for field, value in [("head_sha", "b" * 40), ("workflow_id", 321), ("head_branch", "feature"),
                             ("event", "pull_request"), ("status", "in_progress"), ("conclusion", "failure")]:
            changed = copy.deepcopy(replies); changed[run_path]["workflow_runs"][0][field] = value
            with self.assertRaises(policy.Rejected):
                run(changed)


if __name__ == "__main__":
    unittest.main()
