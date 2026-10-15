import json
import subprocess
import unittest
from unittest.mock import patch

import provision_release as provision
import release_policy as policy


class ProvisionReleaseTests(unittest.TestCase):
    repo = 'fixture-owner/vojeto'
    image = 'ghcr.io/fixture-owner/vojeto-client-private'
    sha = 'a' * 40

    def check(self):
        return provision.check(self.repo, self.image, self.sha, self.sha, 'refs/heads/main')

    def error(self, status):
        return subprocess.CalledProcessError(1, ['gh', 'api'], output=json.dumps({'status': status}))

    def test_only_not_found_can_reach_first_publish_after_source_admission_checks(self):
        with patch.object(policy, 'reviewed_source', return_value='User') as source:
            with patch.object(policy, 'api', side_effect=self.error('404')):
                self.assertEqual(self.check(), 'users/fixture-owner/packages/container/vojeto-client-private')
            source.assert_called_once_with(self.repo, self.sha, self.sha, 'refs/heads/main')

    def test_existing_destination_is_never_replaced_even_if_private(self):
        with patch.object(policy, 'reviewed_source', return_value='User'):
            for package in ({'visibility': 'private'}, {'visibility': 'public'}):
                with patch.object(policy, 'api', return_value=package):
                    with self.assertRaises(policy.Rejected):
                        self.check()

    def test_errors_other_than_not_found_never_authorize_first_publish(self):
        with patch.object(policy, 'reviewed_source', return_value='User'):
            for error in (self.error('403'), self.error('429'), self.error('500'),
                          subprocess.CalledProcessError(1, ['gh'], output='unparseable')):
                with patch.object(policy, 'api', side_effect=error):
                    with self.assertRaises(policy.Rejected):
                        self.check()

    def test_foreign_or_launcher_destination_never_contacts_provider(self):
        with patch.object(policy, 'api') as api:
            with patch.object(policy, 'reviewed_source') as source:
                for image in ('ghcr.io/other/vojeto-client-private', 'ghcr.io/fixture-owner/vojeto-launcher-private'):
                    with self.assertRaises(policy.Rejected):
                        provision.check(self.repo, image, self.sha, self.sha, 'refs/heads/main')
                source.assert_not_called()
                api.assert_not_called()

    def test_bad_source_or_missing_main_protection_never_reaches_package_check(self):
        with patch.object(policy, 'reviewed_source', side_effect=policy.Rejected()):
            with patch.object(policy, 'api') as api:
                with self.assertRaises(policy.Rejected):
                    self.check()
                api.assert_not_called()

    def test_readback_requires_owned_private_package_linked_to_repository(self):
        package = {'name': 'vojeto-client-private', 'package_type': 'container',
                   'visibility': 'private', 'owner': {'login': 'fixture-owner'},
                   'repository': {'full_name': self.repo}}
        def verify(value):
            with patch.object(policy, 'api', side_effect=[{'owner': {'type': 'User'}}, value]):
                provision.verify(self.repo, self.image)
        verify(package)
        for mutation in ({'visibility': 'public'}, {'owner': {'login': 'other'}},
                         {'repository': {'full_name': 'fixture-owner/other'}}, {'repository': None}):
            changed = {**package, **mutation}
            with self.assertRaises((policy.Rejected, AttributeError)):
                verify(changed)


if __name__ == '__main__':
    unittest.main()
