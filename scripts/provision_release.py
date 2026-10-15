"""One-time private client destination setup; never a qualified runtime release."""
import argparse
import json
import os
import subprocess

import release_policy as policy


def check(repository, image, source, github_sha, github_ref, *, allow_self_review=False):
    name = policy.destination(image, repository)
    # Match only the configured client; this lane never provisions launchers.
    policy.require(name == 'vojeto-client-private')
    owner_type = policy.reviewed_source(repository, source, github_sha, github_ref,
                                         allow_self_review=allow_self_review)
    owner = repository.split('/')[0]
    path = f'{"orgs" if owner_type == "Organization" else "users"}/{owner}/packages/container/{name}'
    try:
        policy.api(path)
    except subprocess.CalledProcessError as error:
        # Missing access, rate limits and provider failures are not absence.
        try:
            status = json.loads(error.stdout).get('status')
        except (TypeError, ValueError):
            raise policy.Rejected('Private destination absence is not proven') from None
        policy.require(status in ('404', 404))
        return path
    raise policy.Rejected('Destination already exists; use the normal signed publisher')


def verify(repository, image):
    name = policy.destination(image, repository)
    owner = repository.split('/')[0]
    owner_type = policy.api(f'repos/{repository}').get('owner', {}).get('type')
    policy.require(owner_type in ('User', 'Organization'))
    prefix = 'orgs' if owner_type == 'Organization' else 'users'
    package = policy.api(f'{prefix}/{owner}/packages/container/{name}')
    policy.private_package(package, name, owner)
    policy.require(package.get('repository', {}).get('full_name', '').lower() == repository.lower())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('check', 'verify'), required=True)
    args = parser.parse_args()
    try:
        repo = os.environ.get('GITHUB_REPOSITORY', '')
        image = os.environ.get('RELEASE_IMAGE', '')
        if args.mode == 'verify':
            verify(repo, image)
        else:
            setting = os.environ.get('VOJETO_RELEASE_ALLOW_SELF_REVIEW', '')
            policy.require(setting in ('', 'false', 'true'))
            check(repo, image, os.environ.get('EXPECTED_SHA', ''),
                  os.environ.get('GITHUB_SHA', ''), os.environ.get('GITHUB_REF', ''),
                  allow_self_review=setting == 'true')
        print(json.dumps({'destination': image, 'mode': args.mode, 'qualifiedRelease': False}))
    except (ValueError, KeyError, TypeError, AttributeError, OSError, subprocess.SubprocessError):
        raise SystemExit('Private destination setup refused; preserve state and inspect source, access and package metadata.') from None


if __name__ == '__main__':
    main()
