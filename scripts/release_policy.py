"""Read-only admission checks for a protected, private OCI release.

No environment, package, access grant or visibility change is made here.
"""
import argparse
import json
import os
import re
import subprocess


class Rejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise Rejected("release policy rejected")


def destination(image, repository):
    match = re.fullmatch(r"ghcr\.io/([a-z0-9-]+)/([a-z0-9]+(?:[._-][a-z0-9]+)*)", image)
    require(match is not None)
    require(match[1] == repository.split("/")[0].lower())
    return match[2]


def protected_environment(environment, branches, *, allow_self_review=False):
    require(environment.get("name") == "vojeto-release")
    policy = environment.get("deployment_branch_policy")
    require(policy == {"protected_branches": False, "custom_branch_policies": True})
    rules = [rule for rule in environment.get("protection_rules", [])
             if rule.get("type") == "required_reviewers"]
    require(len(rules) == 1)
    self_review = rules[0].get("prevent_self_review")
    require(self_review is True or (allow_self_review is True and self_review is False))
    reviewers = rules[0].get("reviewers", [])
    require(bool(reviewers))
    require(all(reviewer.get("type") in ("User", "Team")
                and isinstance(reviewer.get("reviewer", {}).get("id"), int)
                and reviewer["reviewer"]["id"] > 0 for reviewer in reviewers))
    admitted = branches.get("branch_policies", [])
    require(branches.get("total_count") == 1 and len(admitted) == 1)
    require(admitted[0].get("name") == "main" and admitted[0].get("type") == "branch")


def private_package(package, name, owner):
    require(package.get("name") == name and package.get("package_type") == "container")
    require(package.get("visibility") == "private")
    require(package.get("owner", {}).get("login", "").lower() == owner.lower())


def api(path):
    result = subprocess.run(["gh", "api", path], check=True, capture_output=True,
                            text=True, timeout=30)
    return json.loads(result.stdout)


def preflight(repository, image, expected_sha, github_sha, github_ref, *, allow_self_review=False):
    require(re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository) is not None)
    require(re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None)
    require(expected_sha == github_sha and github_ref == "refs/heads/main")
    name = destination(image, repository)
    owner = repository.split("/")[0]
    repo = api(f"repos/{repository}")
    owner_type = repo.get("owner", {}).get("type")
    require(owner_type in ("User", "Organization"))
    protected_environment(api(f"repos/{repository}/environments/vojeto-release"),
                          api(f"repos/{repository}/environments/vojeto-release/deployment-branch-policies"),
                          allow_self_review=allow_self_review)
    prefix = "orgs" if owner_type == "Organization" else "users"
    package_path = f"{prefix}/{owner}/packages/container/{name}"
    private_package(api(package_path), name, owner)
    require(api(f"repos/{repository}/commits/{github_sha}")["commit"]["verification"]["verified"] is True)
    workflow = api(f"repos/{repository}/actions/workflows/validate.yml")
    require(workflow.get("path") == ".github/workflows/validate.yml" and workflow.get("state") == "active")
    runs = api(f"repos/{repository}/actions/workflows/validate.yml/runs?head_sha={github_sha}&event=push&per_page=100")
    require(any(run.get("workflow_id") == workflow["id"] and run.get("head_sha") == github_sha
                and run.get("head_branch") == "main" and run.get("event") == "push"
                and run.get("status") == "completed" and run.get("conclusion") == "success"
                for run in runs.get("workflow_runs", [])))
    # Refuse re-publication under an existing source tag; never move rollback pins.
    page = 1
    while page <= 1000:
        versions = api(f"{package_path}/versions?per_page=100&page={page}")
        require(isinstance(versions, list))
        require(not any(expected_sha in version.get("metadata", {}).get("container", {}).get("tags", [])
                        for version in versions))
        if len(versions) < 100:
            return
        page += 1
    raise Rejected("release inventory exceeds admission bound")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args()
    try:
        review_setting = os.environ.get("VOJETO_RELEASE_ALLOW_SELF_REVIEW", "")
        require(review_setting in ("", "false", "true"))
        preflight(os.environ.get("GITHUB_REPOSITORY", ""), args.image, args.expected_sha,
                  os.environ.get("GITHUB_SHA", ""), os.environ.get("GITHUB_REF", ""),
                  allow_self_review=review_setting == "true")
    except (ValueError, KeyError, TypeError, AttributeError, OSError, subprocess.SubprocessError):
        raise SystemExit("Release refused: protected environment, private package, exact source or CI evidence is missing.") from None


if __name__ == "__main__":
    main()
