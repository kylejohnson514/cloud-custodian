# Copyright 2019 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from .common import BaseTest
import time
import json


class BackupTest(BaseTest):

    def test_augment(self):
        factory = self.replay_flight_data("test_backup_augment")
        p = self.load_policy({
            'name': 'all-backup',
            'resource': 'aws.backup-plan'}, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        plan = resources.pop()
        self.assertEqual(
            plan['Tags'],
            [{'Key': 'App', 'Value': 'Backups'}])
        self.assertTrue('Rules' in plan)

        self.assertEqual(
            p.resource_manager.get_arns([plan]),
            [plan['BackupPlanArn']])
        resources = p.resource_manager.get_resources([plan['BackupPlanId']])
        self.assertEqual(len(resources), 1)


class BackupPlanTest(BaseTest):

    def test_backup_plan_tag_untag(self):
        factory = self.replay_flight_data("test_backup_plan_tag_untag")
        p = self.load_policy(
            {
                "name": "backup-plan-tag",
                "resource": "backup-plan",
                "filters": [{"tag:target-tag": "present"}],
                "actions": [
                    {"type": "remove-tag", "tags": ["target-tag"]},
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = factory().client("backup")
        tag = client.list_tags(ResourceArn=resources[0]['BackupPlanArn'])
        self.assertEqual(len(tag.get('Tags')), 0)


class BackupVaultTest(BaseTest):

    def test_backup_get_resources(self):
        factory = self.replay_flight_data('test_backup_vault_get_resources')
        p = self.load_policy({
            "name": "backup-vault", "resource": "backup-vault"},
            session_factory=factory)
        resources = p.resource_manager.get_resources(['Default'])
        self.assertEqual(
            resources[0]['Tags'],
            [{'Key': 'target-tag', 'Value': 'target-value'}])

    def test_backup_vault_tag_untag(self):
        factory = self.replay_flight_data("test_backup_vault_tag_untag")
        p = self.load_policy(
            {
                "name": "backup-vault-tag",
                "resource": "backup-vault",
                "filters": [{"tag:target-tag": "present"}],
                "actions": [
                    {"type": "remove-tag", "tags": ["target-tag"]},
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = factory().client("backup")
        tag = client.list_tags(ResourceArn=resources[0]['BackupVaultArn'])
        self.assertEqual(len(tag.get('Tags')), 0)

    def test_backup_vault_kms_filter(self):
        session_factory = self.replay_flight_data('test_backup_vault_kms_filter')
        kms = session_factory().client('kms')
        p = self.load_policy(
            {
                'name': 'test-backup-vault-kms-filter',
                'resource': 'backup-vault',
                'filters': [
                    {
                        'type': 'kms-key',
                        'key': 'c7n:AliasName',
                        'value': 'alias/aws/backup'
                    }
                ]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertTrue(len(resources), 1)
        aliases = kms.list_aliases(KeyId=resources[0]['EncryptionKeyArn'])
        self.assertEqual(aliases['Aliases'][0]['AliasName'], 'alias/aws/backup')

    def test_backup_vault_modify_policy_add_statements(self):
        session_factory = self.replay_flight_data("test_backup_vault_modify_policy_add_statements")
        client = session_factory().client("backup")
        backup_vault = client.create_backup_vault(
            BackupVaultName="test_backup_vault_modify_policy_add_statements"
        )

        backup_vault_name = backup_vault["BackupVaultName"]
        backup_vault_arn = backup_vault["BackupVaultArn"]

        def cleanup():
            client.delete_backup_vault(BackupVaultName=backup_vault_name)
            if self.recording:
                time.sleep(60)

        self.addCleanup(cleanup)

        client.put_backup_vault_access_policy(
            BackupVaultName=backup_vault_name,
            Policy=json.dumps(
                {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'SpecificAllow',
                            'Effect': 'Allow',
                            'Principal': '*',
                            'Action': ['backup:GetBackupVaultAccessPolicy'],
                            "Resource": backup_vault_arn,
                        },
                    ],
                }
            )
        )

        p = self.load_policy(
            {
                "name": "test-backup-vault-modify-policy-add-statements",
                "resource": "backup-vault",
                "filters": [
                    {"BackupVaultName": backup_vault_name}
                ],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [
                            {
                                "Sid": "AddMe",
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::123456789123:root"},
                                "Action": ["backup:PutBackupVaultAccessPolicy"],
                                "Resource": backup_vault_arn,
                            }
                        ],
                        "remove-statements": [],
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        if self.recording:
            time.sleep(30)

        self.assertEqual(len(resources), 1)
        data = json.loads(
            client.get_backup_vault_access_policy(
                BackupVaultName=resources[0]["BackupVaultName"]
            )["Policy"]
        )

        self.assertTrue("SpecificAllow" in [s["Sid"] for s in data.get("Statement", ())])
        self.assertTrue("AddMe" in [s["Sid"] for s in data.get("Statement", ())])

    def test_backup_vault_modify_policy_remove_statements(self):
        session_factory = self.replay_flight_data(
            "test_backup_vault_modify_policy_remove_statements"
        )
        client = session_factory().client("backup")
        backup_vault = client.create_backup_vault(
            BackupVaultName="test_backup_vault_modify_policy_remove_statements"
        )

        backup_vault_name = backup_vault["BackupVaultName"]
        backup_vault_arn = backup_vault["BackupVaultArn"]

        def cleanup():
            client.delete_backup_vault(BackupVaultName=backup_vault_name)
            if self.recording:
                time.sleep(60)

        self.addCleanup(cleanup)

        client.put_backup_vault_access_policy(
            BackupVaultName=backup_vault_name,
            Policy=json.dumps(
                {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Sid': 'SpecificAllow',
                            'Effect': 'Allow',
                            'Principal': '*',
                            'Action': ['backup:GetBackupVaultAccessPolicy'],
                            "Resource": backup_vault_arn,
                        },
                        {
                            "Sid": "RemoveMe",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789123:root"},
                            "Action": ["backup:PutBackupVaultAccessPolicy"],
                            "Resource": backup_vault_arn,
                        }
                    ],
                }
            )
        )

        p = self.load_policy(
            {
                "name": "test-backup-vault-modify-policy-add-statements",
                "resource": "backup-vault",
                "filters": [
                    {"BackupVaultName": backup_vault_name}
                ],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [],
                        "remove-statements": ["RemoveMe"],
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        if self.recording:
            time.sleep(30)

        self.assertEqual(len(resources), 1)
        data = json.loads(
            client.get_backup_vault_access_policy(
                BackupVaultName=resources[0]["BackupVaultName"]
            )["Policy"]
        )

        self.assertTrue("SpecificAllow" in [s["Sid"] for s in data.get("Statement", ())])
        self.assertFalse("RemoveMe" in [s["Sid"] for s in data.get("Statement", ())])

    def test_backup_vault_modify_add_remove_statements(self):
        session_factory = self.replay_flight_data(
            "test_backup_vault_modify_add_remove_statements"
        )
        client = session_factory().client("backup")
        backup_vault = client.create_backup_vault(
            BackupVaultName="test_backup_vault_modify_add_remove_statements"
        )

        backup_vault_name = backup_vault["BackupVaultName"]
        backup_vault_arn = backup_vault["BackupVaultArn"]

        def cleanup():
            client.delete_backup_vault(BackupVaultName=backup_vault_name)
            if self.recording:
                time.sleep(60)

        self.addCleanup(cleanup)

        client.put_backup_vault_access_policy(
            BackupVaultName=backup_vault_name,
            Policy=json.dumps(
                {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            "Sid": "RemoveMe",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789123:root"},
                            "Action": ["backup:PutBackupVaultAccessPolicy"],
                            "Resource": backup_vault_arn,
                        }
                    ],
                }
            )
        )

        p = self.load_policy(
            {
                "name": "test-backup-vault-modify-policy-add-statements",
                "resource": "backup-vault",
                "filters": [
                    {"BackupVaultName": backup_vault_name}
                ],
                "actions": [
                    {
                        "type": "modify-policy",
                        "add-statements": [
                            {
                                "Sid": "AddMe",
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::123456789123:root"},
                                "Action": ["backup:PutBackupVaultAccessPolicy"],
                                "Resource": backup_vault_arn,
                            }
                        ],
                        "remove-statements": ["RemoveMe"],
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        if self.recording:
            time.sleep(30)

        self.assertEqual(len(resources), 1)
        data = json.loads(
            client.get_backup_vault_access_policy(
                BackupVaultName=resources[0]["BackupVaultName"]
            )["Policy"]
        )

        self.assertTrue("AddMe" in [s["Sid"] for s in data.get("Statement", ())])
        self.assertFalse("RemoveMe" in [s["Sid"] for s in data.get("Statement", ())])
