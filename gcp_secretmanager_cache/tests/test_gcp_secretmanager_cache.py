# -*- coding: utf-8 -*-
"""
This modules purpose is to test bqtools-json

"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import datetime
import logging
import pprint
from time import sleep
import google.auth
import google_crc32c
from google.api_core import exceptions
from google.cloud import secretmanager, secretmanager_v1
import unittest


from gcp_secretmanager_cache import GCPCachedSecret, NoActiveSecretVersion

def setup_module():
    logging.basicConfig(level=logging.DEBUG)
    # ID of the secret to create.
    credentials, project_id = google.auth.default()
    for secret_id in ["NEVER_EXISTS_SECRET",
                      "EMPTY_SECRET",
                      "SECRET_1_VERSION",
                      "SECRET_ALL_DISABLED",
                      "SECRET_ENABLE_THEN_DISABLE",
                      "SECRET_ENABLE_THEN_DISABLE_PAUSE",
                      "SECRET_2_VERSION_PAUSE"]:

        TestScannerMethods.delete_secret(project_id,secret_id)

def teardown_module():
    setup_module()

class TestScannerMethods(unittest.TestCase):
    def setUp(self):
        self.client = secretmanager.SecretManagerServiceClient()
        credentials, project_id  = google.auth.default()
        self.credentials = credentials
        self.project_id = project_id


    @staticmethod
    def delete_secret(project_id, secret_id):
        # Build the parent name from the project.
        parent = f"projects/{project_id}"
        response = None
        client = secretmanager.SecretManagerServiceClient()

        name = client.secret_path(project_id, secret_id)

        exists = True
        try:
            response = client.get_secret(request={"name": name})
        except exceptions.NotFound as e:
            exists = False

        if exists:
            response = client.delete_secret(request={"name": name})
        return response

    def add_secret(self, secret_id):
        # Build the parent name from the project.
        parent = f"projects/{self.project_id}"

        name = self.client.secret_path(self.project_id, secret_id)

        exists = True
        try:
            response = self.client.get_secret(request={"name": name})
        except exceptions.NotFound as e:
            exists = False

        if not exists:
            response = self.client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                }
            )
        return response

    def test_missing_secret(self):

        name = self.client.secret_path(self.project_id, "NEVER_EXISTS_SECRET")
        secret_cache = GCPCachedSecret(name)
        try:
            secret_stuff = secret_cache.get_secret()
        except exceptions.NotFound as e:
            pass

    def setup_test_missing_secret_version(self):
        secret_id = "EMPTY_SECRET"
        name = self.client.secret_path(self.project_id, secret_id)
        parent = f"projects/{self.project_id}"
        # Create the secret.
        response = self.client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            }
        )
        return response

    def test_missing_secret_version(self):

        name = self.client.secret_path(self.project_id, "EMPTY_SECRET")
        secret_cache = GCPCachedSecret(name)
        try:
            secret_stuff = secret_cache.get_secret()
        except NoActiveSecretVersion as e:
            pass

    def setup_test_happy_path_versions(self,payload=None,secret_id=None):
        if not payload:
            payload = "dodgy secret 1"

        if not secret_id:
            secret_id = "SECRET_1_VERSION"

        self.add_secret(secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = payload.encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)
        parent = self.client.secret_path(self.project_id,secret_id)

        # Add the secret version.
        response = self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )
        return response

    def test_happy_path_versions(self):

        name = self.client.secret_path(self.project_id, "SECRET_1_VERSION")
        secret_cache = GCPCachedSecret(name)
        secret_version1_get = secret_cache.get_secret()
        assert secret_version1_get.decode("utf-8") == "dodgy secret 1", "Secret not what is expected"
        secret_version2 = self.setup_test_happy_path_versions("dodgy secret 2")
        secret_version2_get = secret_cache.get_secret()
        assert secret_version2_get.decode(
            "utf-8") == "dodgy secret 1", "Secret not what is expected"
        secret_cache.invalidate_secret()
        secret_version2_get = secret_cache.get_secret()
        assert secret_version2_get.decode(
            "utf-8") == "dodgy secret 2", "Secret not what is expected"


    def setup_test_versions_all_disabled(self,payload=None,secret_id=None):
        if not payload:
            payload = "dodgy secret 1"

        if not secret_id:
            secret_id = "SECRET_ALL_DISABLED"

        self.add_secret(secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = payload.encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)
        parent = self.client.secret_path(self.project_id,secret_id)

        # Add the secret version.
        response = self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )
        self.client.disable_secret_version(
            name=response.name
        )
        return response

    def test_versions_all_disabled(self):

        name = self.client.secret_path(self.project_id, "SECRET_ALL_DISABLED")
        secret_cache = GCPCachedSecret(name)
        try:
            secret_version1_get = secret_cache.get_secret()
            assert 1==0,"Failure on no  secret"
        except NoActiveSecretVersion as e:
            return True

    def setup_test_enabled_then_disable(self,payload=None,secret_id=None):
        if not payload:
            payload = "dodgy secret 1"

        if not secret_id:
            secret_id = "SECRET_ENABLE_THEN_DISABLE"

        self.add_secret(secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = payload.encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)
        parent = self.client.secret_path(self.project_id,secret_id)

        # Add the secret version.
        response = self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )

        return response

    def test_enabled_then_disable(self):
        name = self.client.secret_path(self.project_id, "SECRET_ENABLE_THEN_DISABLE")
        secret_cache = GCPCachedSecret(name)
        secret_cache.get_secret()
        request = secretmanager_v1.ListSecretVersionsRequest(
            parent=name,
            filter="state=ENABLED"
        )
        page_result = self.client.list_secret_versions(request=request)
        for response in page_result:
            self.client.disable_secret_version(
                name=response.name
            )
        secret_cache.invalidate_secret()
        try:
            secret_cache = secret_cache.get_secret()
            assert 1==0, "Should never get here"
        except NoActiveSecretVersion as e:
            pass

    def setup_test_enabled_then_disable_pause(self,payload=None,secret_id=None):
        if not payload:
            payload = "dodgy secret 1"

        if not secret_id:
            secret_id = "SECRET_ENABLE_THEN_DISABLE_PAUSE"

        self.add_secret(secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = payload.encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)
        parent = self.client.secret_path(self.project_id,secret_id)

        # Add the secret version.
        response = self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )

        return response

    def test_enabled_then_disable_pause(self):
        name = self.client.secret_path(self.project_id, "SECRET_ENABLE_THEN_DISABLE_PAUSE")
        secret_cache = GCPCachedSecret(name)
        secret_cache.get_secret()
        request = secretmanager_v1.ListSecretVersionsRequest(
            parent=name,
            filter="state=ENABLED"
        )
        page_result = self.client.list_secret_versions(request=request)
        for response in page_result:
            self.client.disable_secret_version(
                name=response.name
            )
        try_for = 65.0
        success = False
        while try_for >= 0.0:
            sleep(5.0)
            try_for -= 5.0
            try:
                secret = secret_cache.get_secret()
                logging.getLogger(__name__).info(f"Got secret {try_for} {secret.decode('utf-8')}")
            except NoActiveSecretVersion as e:
                logging.getLogger(__name__).info(f"Secret expired at {try_for}")
                success = True
                break

        assert success, "Should always succeed"

    def setup_test_happy_path_versions_pause(self,payload=None,secret_id=None):
        if not payload:
            payload = "dodgy secret 1"

        if not secret_id:
            secret_id = "SECRET_2_VERSION_PAUSE"

        self.add_secret(secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = payload.encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)
        parent = self.client.secret_path(self.project_id,secret_id)

        # Add the secret version.
        response = self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )
        return response

    def test_happy_path_versions_pause(self):

        name = self.client.secret_path(self.project_id, "SECRET_2_VERSION_PAUSE")
        secret_cache = GCPCachedSecret(name)
        secret_version1_get = secret_cache.get_secret()
        assert secret_version1_get.decode("utf-8") == "dodgy secret 1", "Secret not what is expected"
        secret_version2 = self.setup_test_happy_path_versions_pause("dodgy secret 2")
        try_for = 65.0
        success = False
        while try_for >= 0.0:
            sleep(5.0)
            try_for -= 5.0
            secret_version2_get = secret_cache.get_secret()
            logging.getLogger(__name__).info(f"Got secret in test_happy_path_versions_pause {try_for} {secret_version2_get.decode('utf-8')}")
            if secret_version2_get.decode('utf-8') == "dodgy secret 2":
                success = True
                break

        assert success, "Should always succeed"

def main(argv):
    unittest.main()

if __name__ == '__main__':
    main(sys.argv)
