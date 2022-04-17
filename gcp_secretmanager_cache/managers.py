# -*- coding: utf-8 -*-

import json
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta

import google.auth
import google_crc32c
import pytz
from dateutil import parser
from google.cloud import secretmanager, secretmanager_v1
from google.cloud import storage
from googleapiclient.discovery import build
from gcp_secretmanager_cache.exceptions import NewSecretCreateError

"""
Some frameworks for handling secrets.

Designed to support various secret patterns

add new reap old - At rotation period past last secret adds new secret. But has a means of knowing
                   deleting secrets over rotation period + buffer time old.
blue green       - 2 logical secrets exist blue,green if blue is active the grean secret is
                   updated becomes active blue rotation time later  time later blue is updated
                   becomes active
master manager   - In this strategy a master secret allows access to a resource and is given an
                   user account to update a secret for. The secret may or may not have an expiry 
                   time.
change own       - In this the secret being changes is used as a means to connect to a service to
                   update to a new value.

These are designed to be invoked on events from secret manager see
https://cloud.google.com/secret-manager/docs/secret-rotation
For more on basis. This works in conjunction

This assumes all secrets have in json of format of secret labels to help the helper. 
Expected at a minimum is a label of name. 

The sub class that changes MUST validate the secret_type is of type it ca handle and other label 
values exist.  Config is available from either labels beyond these or from a config file.
{
    "secret_type": "enum (Secret Type)"  # must be valid known enumerator for secret
    "config_bucket" : "string"           # name of a storage bucket to get config for secret
    "config_object" : "string"           # Object in storage config_bucket that holds data that 
    helps
                                         # The concrete secret implementation with data needed to 
                                         # manage the secret. We do thsi as data stored in labels 
                                         # is limited. Each concrete implentation describes what 
                                         # should be in the config object.
                                         # be aware "/" and "." not allowed in label value.
                                         # The blob of config is expected to be utf-8 encoded json
                                         # if one of these is set it is expected the other MUST 
                                         # be as well 
                                            
}
"""


@dataclass
class ChangeSecretMeta:
    secret_type: str
    config: dict
    labels: dict
    secret_resource: dict
    secret_id: str
    rotation_period_seconds: int
    ttl: int

    @property
    def reap_oldest_time(self):
        return datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(
            seconds=int(self.rotation_period_seconds * 1.5))


class SecretRotatorMechanic(ABC):

    @abstractmethod
    def disable_old_secret_versions_material(self,
                                             rotator,
                                             change_meta,
                                             event):
        """
        Abstract method but is used to drive any expiry of old material
        """
        pass

    @abstractmethod
    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        return None

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        return None


class SecretRotator:
    def __init__(self, mechanic, ttl=60, _credentials_callback=None, ):
        self._ttl = ttl
        self._credentials_callback = _credentials_callback
        self._mechanic = mechanic
        self.ns = threading.local()

    @property
    def ttl(self):
        return self._ttl

    @property
    def mechanic(self):
        return self._mechanic

    @property
    def credentials(self):
        if not hasattr(self.ns, "_credentials"):
            if self._credentials_callback is not None:
                _credentials, _project_id = self._credentials_callback()
            else:
                _credentials, _project_id = google.auth.default()
            self.ns._credentials = _credentials
            self.ns._project_id = _project_id
        return self.ns._credentials

    @property
    def _client(self):
        if not hasattr(self.ns, "client"):
            self.ns.client = secretmanager.SecretManagerServiceClient(credentials=self.credentials)
        return self.ns.client

    @property
    def project_id(self):
        if not hasattr(self.ns, "_project_id"):
            credential = self.credentials
        return self.ns.project_id

    def rotate_secret(self, attributes, data):
        """
            This method is designed to handle an event call back of rotation.
            The assumption is that the credentials returned has roles

            "roles/secretmanager.secretVersionManager"
            It requires this role as well as adding new secrets it disables
            old secrets.
            For the management where the existing secret is also required (i.e. changing own
            password)
            Then in addition role
            "roles/secretmanager.secretAccessor"
            Would also be required.
            The credentials also need the rights to manage the secret being rotated whatever that
            is.
        """
        if (attributes["eventType"] != "SECRET_ROTATE" or
                "secretId" not in attributes or
                "labels" not in data or
                "secret_type" not in data["labels"]):
            logging.getLogger(__name__).warning(
                f"Received event that does not meet predicates for secret rotation attributes:"
                f"{json.dumps(attributes)}, data:{data}")
            return

        config = None
        if ("config_bucket" in data["labels"] and
                "config_object" in data["labels"]):
            config = self.load_config(data["labels"]["config_bucket"],
                                      data["labels"]["config_object"])

        # construct change_meta holds data for context for all helpers during change
        # roles/secretmanager.secretVersionManager does not have ability to read secret this is
        # passed
        # The ChangesSecretMeta holds meta data for a secret change
        # we have one of these as many threads maybe being run in parallel
        # passing as an object on stack avoids locks and more complex
        # threading constructs
        change_meta = ChangeSecretMeta(secret_type=data["labels"]["secret_type"],
                                       labels=data["labels"],
                                       config=config,
                                       secret_resource=json.loads(data),
                                       secret_id=attributes["secretId"],
                                       rotation_period_seconds=int(
                                           data["rotation"]["rotationPeriod"][:-1]),
                                       ttl=self.ttl)

        # This is opportunity for concrete class to delete unused
        # secret material if any
        self.mechanic.disable_old_secret_versions_material(self, change_meta, event="PreRotate")

        # Mechanic to disable the secret versions in secrete manager
        num_enabled_secrets = self.disable_old_secret_versions(change_meta)

        # Call back to create a new secret based on secret
        # config in some cases may even create an initial secret
        secret = self.mechanic.create_new_secret(self,
                                                 change_meta,
                                                 num_enabled_secrets)

        # Any test to validate secret is setup correctly
        # Optional to implement should throw exception if fails
        self.mechanic.validate_secret(self,
                                      change_meta,
                                      secret)

        # Now add the secret version
        # stores the secret as a new version
        self.add_new_version(change_meta, secret)

        # Call back to invalidate old secrets if disable_old_secrets
        # not sufficient.
        # This is second chance to invalidate secrets but
        self.mechanic.disable_old_secret_versions_material(self, change_meta, event="PostRotate")

    def load_config(self, bucket, blob_name):
        client = storage.Client(credentials=self.credentials)
        bucket = client.get_bucket(bucket)
        blob = bucket.get_blob(blob_name)
        return json.loads(blob.download_as_bytes().decode("utf-8"))

    def disable_old_secret_versions(self,
                                    change_meta):
        min_age = change_meta.reap_oldest_time

        request = secretmanager_v1.ListSecretVersionsRequest(
            parent=change_meta.secret_id,
            filter="state=ENABLED"
        )
        page_result = self._client.list_secret_versions(request=request)
        to_disable = []
        previous = None

        # Assume 1
        num_active = 1
        num_iter = 0
        for num_iter, response in enumerate(sorted(page_result, key=lambda d: d.create_time)):
            # if set was the previous one
            # we do this to avoid disabling th elatest
            if previous:
                to_disable.append(previous)

            # if the secret is old enough disable it
            if response.created_time < min_age:
                previous = response
            else:
                num_active += 1
                previous = None

        # if no iteration number is zero
        if num_iter == 0:
            num_active = 0

        for disable in to_disable:
            self._client.disable_secret_version(
                name=disable.name
            )

        return num_active

    def add_new_version(self,
                        change_meta,
                        secret):
        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        if not isinstance(secret, bytes):
            if isinstance(secret, dict) or isinstance(secret, list):
                secret = json.dumps(secret)
            if not isinstance(secret, str):
                secret = str(secret)
            secret = secret.encode('utf8')

        # Calculate payload checksum. Passing a checksum in add-version request
        # is optional.
        crc32c = google_crc32c.Checksum()
        crc32c.update(secret)
        parent = change_meta.secret_id

        # Add the secret version.
        response = self._client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": secret, "data_crc32c": int(crc32c.hexdigest(), 16)},
            }
        )
        return response


class APIKeyRotatorMechanic(SecretRotatorMechanic):
    """
    Class to provide mechanic of rotating an api key
    Assumes the config json doc has the required attributes.
    APikeys can have same name so we use the displayName to identify
    previous versions
    """

    def disable_old_secret_versions_material(self,
                                             rotator,
                                             change_meta,
                                             event):

        if event != "PreRotate":
            return

        credentials = rotator.credentials
        reap_older_than = change_meta.reap_older_than

        assert "displayName" in change_meta.config, "APIKEY config must have a template api key " \
                                                    "whch must have a displayName"
        apikeys_service = build('apikeys', 'v2', credentials=credentials)
        loc_api = apikeys_service.projects().locations().keys()

        parent = f"projects/{rotator.project_id}locations/global"
        if "parent" in change_meta.config:
            parent = change_meta.config["parent"]

        psrequest = loc_api.list(
            parent=parent,
            pageSize=300)

        to_delete = []
        while psrequest is not None:
            api_key_list_resp = psrequest.execute()
            for api_key in api_key_list_resp.get('keys', []):
                if api_key["displayName"] == change_meta.config["displayName"]:
                    create_time = parser.parse(api_key["createTime"])
                    # if old enough potential to be deleted
                    if create_time < reap_older_than:
                        to_delete.append(api_key)

            if "nextPageToken" in api_key_list_resp:
                psrequest = loc_api.list(
                    parent=parent,
                    pageSize=300,
                    pageToken=api_key_list_resp["nextPageToken"])
            else:
                psrequest = None

        # lets leave the last one
        # we may have had event handler down for along time
        # avoid over eagerly deleteing
        last = None
        for delete_me in to_delete:
            if not last or last["createTime"] > delete_me["createTime"]:
                last = delete_me

        to_delete = [d for d in to_delete if not last or d["name"] != last["name"]]

        # now delete the keys we no longer need
        for delete_me in to_delete:
            del_req = loc_api.delete(
                name=delete_me["name"]
            )
            del_req.execute()

    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        apikeys_service = build('apikeys', 'v2', credentials=change_meta.credentials)
        loc_api = apikeys_service.projects().locations().keys()
        ops_api = apikeys_service.operations()

        parent = f"projects/{rotator.project_id}locations/global"
        if "parent" in change_meta.config:
            parent = change_meta.config["parent"]

        body = {}
        for key in ["restrictions", "displayName", "annotations"]:
            if key in change_meta.config:
                body[key] = change_meta.config[key]

        req_create = loc_api.create(parent=parent,
                                    body=body)
        op_response = req_create.execute()
        while not op_response.get("done"):
            op_req = ops_api.get(
                name=op_response["name"]
            )
            op_response = op_req.execute()

        if "error" in op_response:
            raise NewSecretCreateError(change_meta.secret_id, body, op_response["error"])

        # Now we can get the resource created
        apikey_resource = op_response["response"]

        keystring_req = loc_api.getKeyString(name=apikey_resource["name"])
        keystring_object = keystring_req.execute()
        return keystring_object["keyString"]

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        return None


class APIKeyRotator(SecretRotatorMechanic):
    """
    Class to provide mechanic of rotating an api key
    Assumes the config json doc has the required attributes.
    APikeys can have same name so we use the displayName to identify
    previous versions
    """

    def disable_old_secret_versions_material(self,
                                             rotator,
                                             change_meta,
                                             event):

        if event != "PreRotate":
            return

        credentials = rotator.credentials
        reap_older_than = change_meta.reap_older_than

        assert "displayName" in change_meta.config, "APIKEY config must have a template api key " \
                                                    "whch must have a displayName"
        apikeys_service = build('apikeys', 'v2', credentials=credentials)
        loc_api = apikeys_service.projects().locations().keys()

        parent = f"projects/{rotator.project_id}locations/global"
        if "parent" in change_meta.config:
            parent = change_meta.config["parent"]

        psrequest = loc_api.list(
            parent=parent,
            pageSize=300)

        pspaged_results = []
        while psrequest is not None:
            api_key_list_resp = psrequest.execute()
            for api_key in api_key_list_resp.get('keys', []):
                if api_key["displayName"] == change_meta.config["displayName"]:
                    createTime = parser.parse(api_key["createTime"])

                    logging.getLogger(__name__).info(f"Found apikey {json.dumps(api_key)}")

            if "nextPageToken" in api_key_list_resp:
                psrequest = loc_api.list(
                    parent=parent,
                    pageSize=300,
                    pageToken=api_key_list_resp["nextPageToken"])
            else:
                psrequest = None

    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        apikeys_service = build('apikeys', 'v2', credentials=change_meta.credential)
        loc_api = apikeys_service.projects().locations().keys()
        ops_api = apikeys_service.operations()

        parent = f"projects/{rotator.project_id}locations/global"
        if "parent" in change_meta.config:
            parent = change_meta.config["parent"]

        body = {}
        for key in ["restrictions", "displayName", "annotations"]:
            if key in change_meta.config:
                body[key] = change_meta.config[key]

        req_create = loc_api.create(parent=parent,
                                    body=body)
        op_response = req_create.execute()
        while not op_response.get("done"):
            op_req = ops_api.get(
                name=op_response["name"]
            )
            op_response = op_req.execute()

        if "error" in op_response:
            raise NewSecretCreateError(change_meta.secret_id, body, op_response["error"])

        # Now we can get the resource created
        apikey_resource = op_response["response"]

        keystring_req = loc_api.getKeyString(name=apikey_resource["name"])
        keystring_object = keystring_req.execute()
        return keystring_object["keyString"]

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        return None
