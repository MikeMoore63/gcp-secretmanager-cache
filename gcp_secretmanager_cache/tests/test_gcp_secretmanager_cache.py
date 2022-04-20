# -*- coding: utf-8 -*-
"""
This modules purpose is to test bqtools-json

"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import faulthandler
import gc
import json
import logging
import os
import signal
import sys
import threading
import unittest
import psycopg2
import pymysql
import pytds
from dataclasses import asdict
from datetime import datetime, timedelta
from time import sleep, perf_counter
from googleapiclient.discovery import build
from google.cloud import storage

import google.auth
import google_crc32c
import pytz
from google.api_core import exceptions
from google.cloud import secretmanager, secretmanager_v1

from gcp_secretmanager_cache import *


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
                      "SECRET_2_VERSION_PAUSE",
                      "TEST_SIMPLE_DECORATOR"
                      "TEST_DECORATOR_KEYWORD",
                      "TEST_NOSECRET_TOSECRET",
                      "TEST_NOSECRET_TOSECRET_PAUSE",
                      "TEST_SECRET_THEN_NOSECRET",
                      "TEST_SECRET_THEN_NOSECRET_PAUSE",
                      "TEST_SECRET_PERF_KEY",
                      "TEST_SECRET_VERSION",
                      "TEST_SECRET_ROTATION_FRAMEWORKS"]:
        TestScannerMethods.delete_secret(project_id, secret_id)
    faulthandler.register(signal.SIGUSR1, file=sys.stderr, all_threads=True, chain=False)


def dump_threads():
    threads_now = ",".join([thread.name for thread in threading.enumerate()])
    print(f"threads now -> {threads_now}", file=sys.stderr)
    # os.kill(os.getpid(), signal.SIGUSR1)


def teardown_module():
    gc.collect()
    setup_module()
    wait = 180.0

    while (len(threading.enumerate()) != 1 and wait > 0.0):
        dump_threads()
        sleep(5.0)
        wait -= 5.0

    dump_threads()


class TestSecretRotatorMechanic(SecretRotatorMechanic):
    def __init__(self):
        super(SecretRotatorMechanic, self).__init__()
        self._meta_data = None
        self._secret = "top secret stuff"

    @property
    def meta_data(self):
        return self._meta_data

    def disable_old_secret_versions_material(self,
                                             rotator,
                                             change_meta,
                                             event):
        self._meta_data = change_meta
        logging.getLogger(__name__).info(f"Event {event}  {json.dumps(asdict(change_meta))}")

    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        logging.getLogger(__name__).info(f"Creating secret  {json.dumps(asdict(change_meta))}")
        return self._secret

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        logging.getLogger(__name__).info(f"Validating secret  {json.dumps(asdict(change_meta))}")
        return None


class TestScannerMethods(unittest.TestCase):
    def setUp(self):
        self.client = secretmanager.SecretManagerServiceClient()
        credentials, project_id = google.auth.default()
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
        del secret_cache

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
        dump_threads()
        name = self.client.secret_path(self.project_id, "EMPTY_SECRET")
        secret_cache = GCPCachedSecret(name)
        try:
            secret_stuff = secret_cache.get_secret()
        except NoActiveSecretVersion as e:
            pass

    def setup_test_happy_path_versions(self, payload=None, secret_id=None):
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
        parent = self.client.secret_path(self.project_id, secret_id)

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
        assert secret_version1_get.decode(
            "utf-8") == "dodgy secret 1", "Secret not what is expected"
        secret_version2 = self.setup_test_happy_path_versions("dodgy secret 2")
        secret_version2_get = secret_cache.get_secret()
        assert secret_version2_get.decode(
            "utf-8") == "dodgy secret 1", "Secret not what is expected"
        secret_cache.invalidate_secret()
        secret_version2_get = secret_cache.get_secret()
        assert secret_version2_get.decode(
            "utf-8") == "dodgy secret 2", "Secret not what is expected"

    def setup_test_versions_all_disabled(self, payload=None, secret_id=None):
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
        parent = self.client.secret_path(self.project_id, secret_id)

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
            assert 1 == 0, "Failure on no  secret"
        except NoActiveSecretVersion as e:
            return True

    def setup_test_enabled_then_disable(self, payload=None, secret_id=None):
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
        parent = self.client.secret_path(self.project_id, secret_id)

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
            assert 1 == 0, "Should never get here"
        except NoActiveSecretVersion as e:
            pass

    def setup_test_enabled_then_disable_pause(self, payload=None, secret_id=None):
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
        parent = self.client.secret_path(self.project_id, secret_id)

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

    def setup_test_happy_path_versions_pause(self, payload=None, secret_id=None):
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
        parent = self.client.secret_path(self.project_id, secret_id)

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
        assert secret_version1_get.decode(
            "utf-8") == "dodgy secret 1", "Secret not what is expected"
        secret_version2 = self.setup_test_happy_path_versions_pause("dodgy secret 2")
        try_for = 65.0
        success = False
        while try_for >= 0.0:
            sleep(5.0)
            try_for -= 5.0
            secret_version2_get = secret_cache.get_secret()
            logging.getLogger(__name__).info(
                f"Got secret in test_happy_path_versions_pause {try_for} "
                f"{secret_version2_get.decode('utf-8')}")
            if secret_version2_get.decode('utf-8') == "dodgy secret 2":
                success = True
                break

        assert success, "Should always succeed"

    def setup_test_decorators(self, payload=None, secret_id=None):
        if not payload:
            payload = "keyword secret"

        if not secret_id:
            secret_id = "TEST_SIMPLE_DECORATOR"

        self.add_secret(secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = payload.encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)
        parent = self.client.secret_path(self.project_id, secret_id)

        # Add the secret version.
        response = self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )

        secret_id = "TEST_DECORATOR_KEYWORD"
        self.add_secret(secret_id)

        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        payload = json.dumps({"username": "bob", "password": "password"}).encode("UTF-8")

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(payload)
        parent = self.client.secret_path(self.project_id, secret_id)

        # Add the secret version.
        response = self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )

        return response

    def test_decorators(self):
        @InjectKeywordedSecretString(
            secret_id=self.client.secret_path(self.project_id, "TEST_DECORATOR_KEYWORD"),
            func_username='username',
            func_password='password')
        def function_to_be_decorated(func_username, func_password, more_stuff=None):
            print(
                f'Something cool is being done with the func_username and func_password arguments '
                f'here {func_username} and {func_password}')
            assert func_username == "bob", "User name needs to be bob"
            assert func_password == "password", "Password needs to be passowrd"
            assert more_stuff == "hello", "In testing we expect another arg"

        @InjectSecretString(
            secret_id=self.client.secret_path(self.project_id, "TEST_SIMPLE_DECORATOR"))
        def function_to_be_decorated2(asecret, fred=None):
            assert asecret == "keyword secret", "key word secret not what we expect from decorator"
            assert fred is None or fred == "hello", "Key word arg not what is expected"

        function_to_be_decorated(more_stuff="hello")
        function_to_be_decorated2()
        function_to_be_decorated2(fred="hello")
        function_to_be_decorated2("hello")

    def setup_test_no_version_then_version(self, secret_id=None):

        if not secret_id:
            secret_id = "TEST_NOSECRET_TOSECRET"

        self.add_secret(secret_id)

    def test_no_version_then_version(self):
        name = self.client.secret_path(self.project_id, "TEST_NOSECRET_TOSECRET")
        secret_cache = GCPCachedSecret(name)
        try:
            secret_cache.get_secret()
            assert 1 == 0, "Should never get a version"
        except NoActiveSecretVersion:
            pass
        self.setup_test_happy_path_versions(payload="a secret", secret_id="TEST_NOSECRET_TOSECRET")
        secret_cache.invalidate_secret()
        secret_cache.get_secret()

    def setup_test_no_version_then_version_pause(self):
        self.setup_test_no_version_then_version(secret_id="TEST_NOSECRET_TOSECRET_PAUSE")

    def test_no_version_then_version_pause(self):
        name = self.client.secret_path(self.project_id, "TEST_NOSECRET_TOSECRET_PAUSE")
        secret_cache = GCPCachedSecret(name)
        try:
            secret_cache.get_secret()
            assert 1 == 0, "Should never get a version"
        except NoActiveSecretVersion:
            pass
        self.setup_test_happy_path_versions(payload="a secret",
                                            secret_id="TEST_NOSECRET_TOSECRET_PAUSE")
        sleep(65.0)
        secret_cache.get_secret()

    def setup_test_secret_then_no_secret(self):
        self.setup_test_happy_path_versions(payload="a secret",
                                            secret_id="TEST_SECRET_THEN_NOSECRET")

    def test_secret_then_no_secret(self):
        name = self.client.secret_path(self.project_id, "TEST_SECRET_THEN_NOSECRET")
        secret_cache = GCPCachedSecret(name)
        secret = secret_cache.get_secret()
        self.delete_secret(self.project_id, "TEST_SECRET_THEN_NOSECRET")
        secret_cache.invalidate_secret()
        try:
            secret = secret_cache.get_secret()
            assert 1 == 0, "Should not get here"
        except exceptions.NotFound as e:
            pass

    def setup_test_secret_then_no_secret_pause(self):
        self.setup_test_happy_path_versions(payload="a secret",
                                            secret_id="TEST_SECRET_THEN_NOSECRET_PAUSE")

    def test_secret_then_no_secret_pause(self):
        name = self.client.secret_path(self.project_id, "TEST_SECRET_THEN_NOSECRET_PAUSE")
        secret_cache = GCPCachedSecret(name)
        secret = secret_cache.get_secret()
        self.delete_secret(self.project_id, "TEST_SECRET_THEN_NOSECRET_PAUSE")
        sleep(65.0)
        try:
            secret = secret_cache.get_secret()
            assert 1 == 0, "Should not get here"
        except exceptions.NotFound as e:
            pass

    def setup_test_performance(self):
        self.setup_test_happy_path_versions(payload="a secret",
                                            secret_id="TEST_SECRET_PERF_KEY")

    def test_test_performance(self):
        name = self.client.secret_path(self.project_id, "TEST_SECRET_PERF_KEY")
        secret_cache = GCPCachedSecret(name)
        tic = perf_counter()
        secret = secret_cache.get_secret()
        toc = perf_counter()
        print(f"Downloaded the initial secret in {toc - tic:0.4f} seconds", file=sys.stderr)
        tic = perf_counter()
        loopyloop = 5000000
        for i in range(0, loopyloop):
            secret = secret_cache.get_secret()
        toc = perf_counter()
        print(
            f"Downloaded the secret {loopyloop:,d} times in {(toc - tic):0.4f} seconds and at an "
            f"average time of {(toc - tic) / loopyloop:0.10f} seconds",
            file=sys.stderr)

    def setup_test_version(self):
        self.setup_test_happy_path_versions(payload="1",
                                            secret_id="TEST_SECRET_VERSION")

    def test_test_version(self):
        name = self.client.secret_path(self.project_id, "TEST_SECRET_VERSION") + "/versions/1"
        secret_cache = GCPCachedSecret(name)
        secret = secret_cache.get_secret()
        assert secret.decode(
            "utf-8") == "1", "secret not what is expected"
        self.setup_test_happy_path_versions(payload="2", secret_id="TEST_SECRET_VERSION")
        secret_cache.invalidate_secret()
        secret = secret_cache.get_secret()
        assert secret.decode(
            "utf-8") == "1", "secret not what is expected"
        name2 = self.client.secret_path(self.project_id, "TEST_SECRET_VERSION") + "/versions/2"
        secret_cache2 = GCPCachedSecret(name2)
        secret2 = secret_cache2.get_secret()
        assert secret2.decode(
            "utf-8") == "2", "secret not what is expected"
        secret_cache1 = GCPCachedSecret(name)
        secret = secret_cache1.get_secret()
        assert secret.decode(
            "utf-8") == "1", "secret not what is expected"
        self.client.disable_secret_version(
            name=name2
        )
        secret_cache2.invalidate_secret()
        secret2 = secret_cache2.get_secret()
        assert secret2.decode(
            "utf-8") == "1", "secret not what is expected"

    def test_secret_rotation(self):
        # Build the parent name from the project.
        parent = f"projects/{self.project_id}"
        secret_id = "TEST_SECRET_ROTATION_FRAMEWORKS"

        name = self.client.secret_path(self.project_id, secret_id)

        exists = True
        try:
            response = self.client.get_secret(request={"name": name})
            self.client.delete_secret(
                request={"name": name}
            )
        except exceptions.NotFound as e:
            exists = False

        topic = secretmanager_v1.Topic()
        topic.name = os.getenv("TOPIC", "projects/methodical-bee-162815/topics/foo")
        response = self.client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {
                    "replication":
                        {"automatic": {}
                         },
                    "labels": {
                        "secret_type": "test-rotation",
                    },
                    "rotation": {
                        "rotation_period": timedelta(seconds=3600),
                        "next_rotation_time": datetime.utcnow().replace(tzinfo=pytz.UTC) + timedelta(seconds=3600),
                    },
                    "topics": [
                        topic
                    ]
                }
            }
        )

        rotator_mechanic = TestSecretRotatorMechanic()
        test_rotator = SecretRotator(rotator_mechanic)

        sm_service = build("secretmanager","v1")
        secret_req = sm_service.projects().secrets().get(name=response.name)
        secret_response = secret_req.execute()
        data = json.dumps(secret_response).encode("utf-8")

        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": response.name
        }, data)

        secret_cache = GCPCachedSecret(response.name)
        secret = secret_cache.get_secret()
        assert "top secret stuff" == secret.decode("utf-8"), "Secret on 1st rotation not what is expected"
        rotator_mechanic._secret = "top secret stuff2"
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": response.name
        }, data)
        secret_cache.invalidate_secret()
        secret = secret_cache.get_secret()
        assert "top secret stuff2" == secret.decode("utf-8"), "Secret has not been rotated for second rotation"

        return response

    def test_api_key_rotation(self):
        # Build the parent name from the project.
        parent = f"projects/{self.project_id}"
        secret_id = "TEST_APIKEY_ROTATION_FRAMEWORKS"

        name = self.client.secret_path(self.project_id, secret_id)

        exists = True
        try:
            response = self.client.get_secret(request={"name": name})
        except exceptions.NotFound as e:
            exists = False

        topic = secretmanager_v1.Topic()
        topic.name = os.getenv("TOPIC", "projects/methodical-bee-162815/topics/foo")
        client = storage.Client()
        bucket_name = os.getenv("BUCKET", "methodical-bee-162815-secret")
        try:
            bucket = client.get_bucket(bucket_name)
        except exceptions.NotFound as e:
            bucket = client.create_bucket(
                bucket_name
            )

        blob = bucket.blob("test-apikey")

        try:
            blob.delete()
        except exceptions.NotFound as e:
            pass

        blob.upload_from_string(json.dumps({
            "displayName": "A test api key to test rotation",
            "restrictions": {
                "apiTargets": [
                    {
                        "service": "datastudio.googleapis.com"
                    }
                ]
            }
        }).encode("utf-8"))

        if not exists:
            response = self.client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {
                        "replication":
                            {"automatic": {}
                             },
                        "labels": {
                            "secret_type": "google-apikey",
                            "config_bucket": bucket_name,
                            "config_object": "test-apikey"
                        },
                        "rotation": {
                            "rotation_period": timedelta(seconds=3600),
                            "next_rotation_time": datetime.utcnow().replace(
                                tzinfo=pytz.UTC) + timedelta(seconds=3600),
                        },
                        "topics": [
                            topic
                        ]
                    }
                }
            )

        sm_service = build("secretmanager", "v1")
        secret_req = sm_service.projects().secrets().get(name=name)
        secret_response = secret_req.execute()
        data = json.dumps(secret_response).encode("utf-8")

        rotator_mechanic = APIKeyRotator()
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 2 is {json.dumps(secret2)}")
        assert secret["keyString"] != secret2["keyString"], "Initial key and second key are not the same"

    def test_sa_key_rotation(self):
        # Build the parent name from the project.
        parent = f"projects/{self.project_id}"
        secret_id = "TEST_SAKEY_ROTATION_FRAMEWORKS"

        name = self.client.secret_path(self.project_id, secret_id)

        exists = True
        try:
            response = self.client.get_secret(request={"name": name})
        except exceptions.NotFound as e:
            exists = False

        topic = secretmanager_v1.Topic()
        topic.name = os.getenv("TOPIC", "projects/methodical-bee-162815/topics/foo")
        client = storage.Client()
        bucket_name = os.getenv("BUCKET", "methodical-bee-162815-secret")
        try:
            bucket = client.get_bucket(bucket_name)
        except exceptions.NotFound as e:
            bucket = client.create_bucket(
                bucket_name
            )

        blob = bucket.blob("test-sakey")

        try:
            blob.delete()
        except exceptions.NotFound as e:
            pass

        blob.upload_from_string(json.dumps({
            "name": "projects/methodical-bee-162815/serviceAccounts/test-rotate@methodical-bee-162815.iam.gserviceaccount.com"
        }).encode("utf-8"))

        if not exists:
            response = self.client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {
                        "replication":
                            {"automatic": {}
                             },
                        "labels": {
                            "secret_type": "google-serviceaccount",
                            "config_bucket": bucket_name,
                            "config_object": "test-sakey"
                        },
                        "rotation": {
                            "rotation_period": timedelta(seconds=3600),
                            "next_rotation_time": datetime.utcnow().replace(
                                tzinfo=pytz.UTC) + timedelta(seconds=3600),
                        },
                        "topics": [
                            topic
                        ]
                    }
                }
            )

        sm_service = build("secretmanager", "v1")
        secret_req = sm_service.projects().secrets().get(name=name)
        secret_response = secret_req.execute()
        data = json.dumps(secret_response).encode("utf-8")

        rotator_mechanic = SAKeyRotator()
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 2 is {json.dumps(secret2)}")
        assert secret["privateKeyData"] != secret2["privateKeyData"], "Initial key and second key are not the same"

    def test_postgres_db_rotator(self):

        # if env not set skip this
        if "DBPGSUPASSWORD" not in os.environ:
            return

        # Build the parent name from the project.
        parent = f"projects/{self.project_id}"
        secret_id = "TEST_DBPGSUKEY_ROTATION_FRAMEWORKS"

        name = self.client.secret_path(self.project_id, secret_id)

        exists = True
        try:
            response = self.client.get_secret(request={"name": name})
        except exceptions.NotFound as e:
            exists = False

        topic = secretmanager_v1.Topic()
        topic.name = os.getenv("TOPIC", "projects/methodical-bee-162815/topics/foo")
        client = storage.Client()
        bucket_name = os.getenv("BUCKET", "methodical-bee-162815-secret")
        try:
            bucket = client.get_bucket(bucket_name)
        except exceptions.NotFound as e:
            bucket = client.create_bucket(
                bucket_name
            )

        blob = bucket.blob("test-dbpgsukey")

        try:
            blob.delete()
        except exceptions.NotFound as e:
            pass

        blob.upload_from_string(json.dumps({
            "server_properties": {"host": "127.0.0.1",
                                  "port": 5432,
                                  "dbname": "test"
                                  },
            "initial_secret": {
                "user": "mike",
                "password": os.environ["DBPGSUPASSWORD"]
            }
        }).encode("utf-8"))

        if not exists:
            response = self.client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {
                        "replication":
                            {"automatic": {}
                             },
                        "labels": {
                            "secret_type": "database-api",
                            "config_bucket": bucket_name,
                            "config_object": "test-dbpgsukey"
                        },
                        "rotation": {
                            "rotation_period": timedelta(seconds=3600),
                            "next_rotation_time": datetime.utcnow().replace(
                                tzinfo=pytz.UTC) + timedelta(seconds=3600),
                        },
                        "topics": [
                            topic
                        ]
                    }
                }
            )

        sm_service = build("secretmanager", "v1")
        secret_req = sm_service.projects().secrets().get(name=name)
        secret_response = secret_req.execute()

        data = json.dumps(secret_response).encode("utf-8")

        # test master user for same secret
        # we do this as we can destroy everything bar master_secret
        rotator_mechanic = DBApiMasterUserPasswordRotator(db=psycopg2,
                                                          statement=DBApiMasterUserPasswordRotatorConstants.PG,
                                                          master_secret="projects/231925320579/secrets/TEST_PG_MASTER_SECRET")
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 2 is {json.dumps(secret2)}")
        assert secret["password"] != secret2[
            "password"], "Initial key and second key are not the same"

        # test single user
        rotator_mechanic = DBApiSingleUserPasswordRotator(db=psycopg2,
                                                          statement=DBApiSingleUserPasswordRotatorConstants.PG)
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 2 is {json.dumps(secret2)}")
        assert secret["password"] != secret2[
            "password"], "Initial key and second key are not the same"






    def test_mysql_db_rotator(self):

        # if env not set skip this
        if "DBMYSQLSUPASSWORD" not in os.environ:
            return

        # Build the parent name from the project.
        parent = f"projects/{self.project_id}"
        secret_id = "TEST_DBMYSQLSUKEY_ROTATION_FRAMEWORKS"

        name = self.client.secret_path(self.project_id, secret_id)

        exists = True
        try:
            response = self.client.get_secret(request={"name": name})
        except exceptions.NotFound as e:
            exists = False

        topic = secretmanager_v1.Topic()
        topic.name = os.getenv("TOPIC", "projects/methodical-bee-162815/topics/foo")
        client = storage.Client()
        bucket_name = os.getenv("BUCKET", "methodical-bee-162815-secret")
        try:
            bucket = client.get_bucket(bucket_name)
        except exceptions.NotFound as e:
            bucket = client.create_bucket(
                bucket_name
            )

        blob = bucket.blob("test-dbmysqlsukey")

        try:
            blob.delete()
        except exceptions.NotFound as e:
            pass

        blob.upload_from_string(json.dumps({
            "server_properties": {"host": "127.0.0.1",
                                  "port": 5434
                                  },
            "initial_secret": {
                "user": "mike",
                "password": os.environ["DBMYSQLSUPASSWORD"]
            }
        }).encode("utf-8"))

        if not exists:
            response = self.client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {
                        "replication":
                            {"automatic": {}
                             },
                        "labels": {
                            "secret_type": "database-api",
                            "config_bucket": bucket_name,
                            "config_object": "test-dbmysqlsukey"
                        },
                        "rotation": {
                            "rotation_period": timedelta(seconds=3600),
                            "next_rotation_time": datetime.utcnow().replace(
                                tzinfo=pytz.UTC) + timedelta(seconds=3600),
                        },
                        "topics": [
                            topic
                        ]
                    }
                }
            )

        sm_service = build("secretmanager", "v1")
        secret_req = sm_service.projects().secrets().get(name=name)
        secret_response = secret_req.execute()
        data = json.dumps(secret_response).encode("utf-8")

        # Master user test

        rotator_mechanic = DBApiMasterUserPasswordRotator(db=pymysql,
                                                          statement=DBApiMasterUserPasswordRotatorConstants.MYSQL,
                                                          master_secret="projects/231925320579/secrets/TEST_MYSQL_MASTER_SECRET")
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 2 is {json.dumps(secret2)}")
        assert secret["password"] != secret2[
            "password"], "Initial key and second key are not the same"

        # Single user
        rotator_mechanic = DBApiSingleUserPasswordRotator(db=pymysql,
                                                          statement=DBApiSingleUserPasswordRotatorConstants.MYSQL)
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"API key secret 2 is {json.dumps(secret2)}")
        assert secret["password"] != secret2[
            "password"], "Initial key and second key are not the same"

    def test_mssql_db_rotator(self):

        # if env not set skip this
        if "DBMSSQLSUPASSWORD" not in os.environ:
            return

        # Build the parent name from the project.
        parent = f"projects/{self.project_id}"
        secret_id = "TEST_DBMSSQLSUKEY_ROTATION_FRAMEWORKS"

        name = self.client.secret_path(self.project_id, secret_id)

        exists = True
        try:
            response = self.client.get_secret(request={"name": name})
        except exceptions.NotFound as e:
            exists = False

        topic = secretmanager_v1.Topic()
        topic.name = os.getenv("TOPIC", "projects/methodical-bee-162815/topics/foo")
        client = storage.Client()
        bucket_name = os.getenv("BUCKET", "methodical-bee-162815-secret")
        try:
            bucket = client.get_bucket(bucket_name)
        except exceptions.NotFound as e:
            bucket = client.create_bucket(
                bucket_name
            )

        blob = bucket.blob("test-dbmssqlsukey")

        try:
            blob.delete()
        except exceptions.NotFound as e:
            pass

        blob.upload_from_string(json.dumps({
            "server_properties": {
                                    "dsn": "127.0.0.1",
                                    "port": 5433
                                 },
            "initial_secret": {
                "user": "mike",
                "password": os.environ["DBMSSQLSUPASSWORD"]
            }
        }).encode("utf-8"))

        if not exists:
            response = self.client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {
                        "replication":
                            {"automatic": {}
                             },
                        "labels": {
                            "secret_type": "database-api",
                            "config_bucket": bucket_name,
                            "config_object": "test-dbmssqlsukey"
                        },
                        "rotation": {
                            "rotation_period": timedelta(seconds=3600),
                            "next_rotation_time": datetime.utcnow().replace(
                                tzinfo=pytz.UTC) + timedelta(seconds=3600),
                        },
                        "topics": [
                            topic
                        ]
                    }
                }
            )

        sm_service = build("secretmanager", "v1")
        secret_req = sm_service.projects().secrets().get(name=name)
        secret_response = secret_req.execute()
        data = json.dumps(secret_response).encode("utf-8")

        # multi user rotator
        rotator_mechanic = DBApiMasterUserPasswordRotator(db=pytds,
                                                          statement=DBApiMasterUserPasswordRotatorConstants.MSSQL,
                                                          master_secret="projects/231925320579/secrets/TEST_MSSQL_MASTER_SECRET")
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"MS SQL Sever secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"MS SQL Sever secret 2 is {json.dumps(secret2)}")
        assert secret["password"] != secret2[
            "password"], "Initial key and second key are not the same"

        # single use rotator
        rotator_mechanic = DBApiSingleUserPasswordRotator(db=pytds,
                                                          statement=DBApiSingleUserPasswordRotatorConstants.MSSQL)
        test_rotator = SecretRotator(rotator_mechanic)
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)

        secret_cache = GCPCachedSecret(name)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"MS SQL Sever secret 1 is {json.dumps(secret)}")
        test_rotator.rotate_secret({
            "eventType": "SECRET_ROTATE",
            "secretId": name
        }, data)
        secret_cache.invalidate_secret()
        secret2 = json.loads(secret_cache.get_secret().decode("utf-8"))
        logging.getLogger(__name__).info(f"MS SQL Sever secret 2 is {json.dumps(secret2)}")
        assert secret["password"] != secret2[
            "password"], "Initial key and second key are not the same"

def main(argv):
    unittest.main()


if __name__ == '__main__':
    main(sys.argv)
