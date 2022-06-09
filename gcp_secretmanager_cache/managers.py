# -*- coding: utf-8 -*-

import base64
import json
import logging
import os
import re
import secrets
import string
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

from gcp_secretmanager_cache.exceptions import NewSecretCreateError, DBPWDInputUnsafe
from .cache_secret import GCPCachedSecret, NoActiveSecretVersion

"""
Some frameworks for handling secrets.

Designed to support various secret patterns

add new reap old - At rotation period past last secret adds new secret. But has a means of knowing
                   deleting secrets over rotation period + buffer time old.
master manager   - In this strategy a master secret allows access to a resource and is given an
                   user account to update a secret for. The secret may or may not have an expiry 
                   time.
single user change own  - In this the secret being changes is used as a means to connect to a 
service to
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

secret_type ENUMS

test-rotation     Used in gcp_secretmanager_cache tests
google-apikey     Used to indicate that the secret is an api key string
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
    def disable_oldest_time(self):
        return datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(
            seconds=int(self.rotation_period_seconds * 1.5))

    @property
    def delete_oldest_time(self):
        return datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(
            seconds=int(self.rotation_period_seconds * 5))

    @property
    def project_id(self):
        return re.search(r"projects/([^/]+)", self.secret_id).group(1)


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
        return self.ns._project_id

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
        data = json.loads(data.decode("utf-8"))
        if (attributes["eventType"] != "SECRET_ROTATE" or
                "secretId" not in attributes or
                "labels" not in data or
                "secret_type" not in data["labels"]):
            logging.getLogger(__name__).warning(
                f"Received event that does not meet predicates for secret rotation attributes:"
                f"{json.dumps(attributes)}, data:{json.dumps(data)}")
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
                                       secret_resource=data,
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
        min_age = change_meta.disable_oldest_time

        request = secretmanager_v1.ListSecretVersionsRequest(
            parent=change_meta.secret_id,
            filter="state!=DESTROYED"
        )
        page_result = self._client.list_secret_versions(request=request)
        to_disable = []
        to_delete = []
        previous = None

        # Assume 1
        num_active = 1
        num_iter = 0
        for num_iter, response in enumerate(sorted(page_result, key=lambda d: d.create_time)):
            # if set was the previous one
            # we do this to avoid disabling th elatest
            if previous and response.state == secretmanager_v1.SecretVersion.State.ENABLED:
                to_disable.append(previous)

            if response.state == secretmanager_v1.SecretVersion.State.DISABLED and \
                    response.create_time < \
                    change_meta.delete_oldest_time:
                to_delete.append(response)

            # if the secret is old enough disable it
            if response.create_time < min_age:
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

        for delete in to_delete:
            self._client.destroy_secret_version(
                name=delete.name
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

        assert change_meta.secret_type == "google-apikey", "Expect secret type to be google-apikey"

        credentials = rotator.credentials

        assert "displayName" in change_meta.config, "APIKEY config must have a template api key " \
                                                    "which must have a displayName"

        apikeys_service = build('apikeys', 'v2', credentials=credentials)
        loc_api = apikeys_service.projects().locations().keys()

        parent = f"projects/{change_meta.project_id}/locations/global"
        if "parent" in change_meta.config:
            parent = change_meta.config["parent"]

        psrequest = loc_api.list(
            parent=parent,
            pageSize=300)

        to_delete = []
        latest = None
        while psrequest is not None:
            api_key_list_resp = psrequest.execute()
            for api_key in api_key_list_resp.get('keys', []):
                if api_key["displayName"] == change_meta.config["displayName"]:
                    createTime = parser.parse(api_key["createTime"])
                    if not latest or createTime > parser.parse(latest["createTime"]):
                        latest = api_key
                    if createTime < change_meta.delete_oldest_time:
                        to_delete.append(api_key)
                        logging.getLogger(__name__).info(
                            f"Found apikey to delete {json.dumps(api_key)}")

            if "nextPageToken" in api_key_list_resp:
                psrequest = loc_api.list(
                    parent=parent,
                    pageSize=300,
                    pageToken=api_key_list_resp["nextPageToken"])
            else:
                psrequest = None

        for delete_key in to_delete:
            if delete_key["createTime"] != latest["createTime"]:
                del_req = loc_api.delete(
                    name=delete_key["name"]
                )
                # returns op but we won't wait
                del_req.execute()
                logging.getLogger(__name__).info(f"Deleted apikey {delete_key['name']}")

    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        apikeys_service = build('apikeys', 'v2', credentials=rotator.credentials)
        loc_api = apikeys_service.projects().locations().keys()
        ops_api = apikeys_service.operations()

        parent = f"projects/{change_meta.project_id}/locations/global"
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
        keystring_object["name"] = apikey_resource["name"]
        return keystring_object

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        return None


class SAKeyRotator(SecretRotatorMechanic):
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

        assert change_meta.secret_type == "google-serviceaccount", "Expect secret type to be " \
                                                                   "google-serviceAccount"

        credentials = rotator.credentials

        assert "name" in change_meta.config, "Service Account key rotator config MUST have a name" \
                                             " key"

        iam_service = build('iam', 'v1', credentials=credentials)
        loc_api = iam_service.projects().serviceAccounts().keys()

        psrequest = loc_api.list(
            name=change_meta.config["name"],
            keyTypes="USER_MANAGED")

        to_disable = []
        to_delete = []
        latest = None

        api_key_list_resp = psrequest.execute()
        for api_key in api_key_list_resp.get('keys', []):
            createTime = parser.parse(api_key["validAfterTime"])
            if not latest or createTime > parser.parse(latest["validAfterTime"]):
                latest = api_key
            if createTime < change_meta.disable_oldest_time and (
                    "disabled" not in api_key or not api_key["disabled"]):
                to_disable.append(api_key)
                logging.getLogger(__name__).info(
                    f"Found sa key to disable {json.dumps(api_key)}")

            if createTime < change_meta.delete_oldest_time:
                to_delete.append(api_key)
                logging.getLogger(__name__).info(f"Found sa key to delete {json.dumps(api_key)}")

        for disable_key in to_disable:
            if disable_key["validAfterTime"] != latest["validAfterTime"]:
                disable_req = loc_api.disable(
                    name=disable_key["name"]
                )
                # returns op but we won't wait
                disable_req.execute()

        for delete_key in to_delete:
            if delete_key["validAfterTime"] != latest["validAfterTime"]:
                del_req = loc_api.delete(
                    name=delete_key["name"]
                )
                # returns op but we won't wait
                del_req.execute()

    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        assert change_meta.secret_type == "google-serviceaccount", "Expect secret type to be " \
                                                                   "google-serviceAccount"

        credentials = rotator.credentials

        assert "name" in change_meta.config, "Service Account key rotator config MUST have a name" \
                                             " key"

        body = {
            "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"
        }
        iam_service = build('iam', 'v1', credentials=credentials)
        loc_api = iam_service.projects().serviceAccounts().keys()
        sakey_req = loc_api.create(name=change_meta.config["name"],
                                   alt="json",
                                   body=body)
        sakey_resp = sakey_req.execute()
        new_key = base64.standard_b64decode(sakey_resp["privateKeyData"])
        return new_key

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        return None


class DBRotator(SecretRotatorMechanic):
    """:cvar
    Class that provides common mechanics for changing database passwords
    """
    BLOCKED_CHARACTERS = ";' \"\\"

    def __init__(self, db, statement, exclude_characters=None, password_length=20, usernamekey=None,
                 passwordkey=None):
        super(DBRotator, self).__init__()
        if not usernamekey:
            usernamekey = "user"
        if not passwordkey:
            passwordkey = "password"

        if not exclude_characters:
            exclude_characters = " ,'\"\\+=%^*~[].{}@&"
        self._db = db
        self._statement = statement
        self._exclude_charaters = exclude_characters
        self._password_length = password_length
        self._usernamekey = usernamekey
        self._passwordkey = passwordkey

    def _generate_password(self):
        letters = string.ascii_letters + string.digits
        password = ""
        while len(password) < self._password_length:
            candidate = secrets.choice(letters)
            if not self._exclude_charaters or candidate not in self._exclude_charaters:
                password = password + candidate
        return password

    @property
    def db(self):
        return self._db

    @property
    def statement(self):
        return self._statement


class DBApiSingleUserPasswordRotatorConstants:
    PG = "ALTER USER {user} WITH PASSWORD '{newpassword}';"
    MARIADB = "SET PASSWORD = PASSWORD('{newpassword}');"
    MYSQL = "SET PASSWORD = PASSWORD('{newpassword}');"
    ORACLE = 'ALTER USER {user} IDENTIFIED BY "{newpassword}"'
    SYBSASE = "sp_password {password}, {newpassword}"
    MSSQL = "ALTER LOGIN {user} WITH PASSWORD = '{newpassword}' OLD_PASSWORD = '{password}';"


class DBApiSingleUserPasswordRotator(DBRotator):
    """
    Class to provide mechanic of rotating a password for a user.
    Requires access to starting secret or an initial secret.
    Assumes server properties for username and password are
    {
        "user":"string",
        "password": "string"
    }

    The constructor is passed in a db-api connection.
    and a statement which can have parameters
    {
        "user": "string",
        "password": "string", # starting password
        "newpassword": "string" # the new password
    }
    """

    def disable_old_secret_versions_material(self,
                                             rotator,
                                             change_meta,
                                             event):

        if event != "PreRotate":
            return

        assert change_meta.secret_type == "database-api", "Expect database api"

    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        assert change_meta.secret_type == "database-api", "Expect secret type to be " \
                                                          "database-api"

        # Get the existing secret if it has a version
        secret_cache = GCPCachedSecret(change_meta.secret_id)

        try:
            secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        # if we get no active version we use the initial secret
        except NoActiveSecretVersion as e:
            secret = change_meta.config["initial_secret"]
            if any(c in self.BLOCKED_CHARACTERS for c in secret["user"]) or \
                    any(c in self.BLOCKED_CHARACTERS for c in secret["password"]):
                raise DBPWDInputUnsafe(change_meta.secret_id, secret["user"])

        secret_modified = {}
        secret_modified[self._usernamekey] = secret["user"]
        secret_modified[self._passwordkey] = secret["password"]

        # config json structure has properties to allow connection
        # these are merged with secret to create connection properties
        server_connection_properties = {**change_meta.config["server_properties"],
                                        **secret_modified}

        conn_kwargs = server_connection_properties
        conn_args = []
        if "connstring" in change_meta.config:
            conn_kwargs = {}
            conn_args.append(
                change_meta.config["connstring"].format_map(server_connection_properties))

        # we generate a new password
        new_password = self._generate_password()

        with self.db.connect(*conn_args, **conn_kwargs) as conn:
            with conn.cursor() as curs:
                try:
                    curs.execute(self.statement.format_map(
                        {**server_connection_properties, **{"newpassword": new_password}}))
                    conn.commit()
                except Exception as e:
                    if type(e).__name__.endswith("ProgrammingError"):
                        logging.getLogger(
                            __name__).exception("While executing {}".format(
                            self.statement.format_map(
                                {**server_connection_properties,
                                 **{"newpassword": new_password}}).replace(
                                secret["password"],
                                "*********")))
                    raise

        new_secret = {"user": secret["user"], "password": new_password}
        return new_secret

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        return None


class DBApiMasterUserPasswordRotatorConstants:
    PG = "ALTER USER {login_user} WITH PASSWORD '{newpassword}';"
    MARIADB = "ALTER USER '{login_user}' IDENTIFIED BY '{newpassword}';"
    MYSQL = "ALTER USER '{login_user}' IDENTIFIED BY '{newpassword}';"
    ORACLE = 'ALTER USER {login_user} IDENTIFIED BY "{newpassword}"'
    SYBSASE = "sp_password {password}, {newpassword} , {login_user};"
    MSSQL = "ALTER LOGIN {login_user} WITH PASSWORD = '{newpassword}';"


class DBApiMasterUserPasswordRotator(DBRotator):
    """
    Class to provide mechanic of rotating a password for a user.
    Requires access to starting secret or an initial secret.
    Assumes server properties for username and password are
    {
        "user":"string",
        "password": "string"
    }

    The constructor is passed in a db-api connection.
    and a statement which can have parameters
    {
        "user": "string",
        "password": "string", # starting password
        "newpassword": "string" # the new password
    }
    """

    def __init__(self, db, statement, exclude_characters=None, password_length=16, usernamekey=None,
                 passwordkey=None, master_secret=None):
        super(DBApiMasterUserPasswordRotator, self).__init__(db,
                                                             statement,
                                                             exclude_characters,
                                                             password_length,
                                                             usernamekey,
                                                             passwordkey)
        self._master_secret = master_secret

    @property
    def master_secret(self):
        return self._master_secret

    def disable_old_secret_versions_material(self,
                                             rotator,
                                             change_meta,
                                             event):

        if event != "PreRotate":
            return

        assert change_meta.secret_type == "database-api", "Expect database-api as secret_type"

    def create_new_secret(self,
                          rotator,
                          change_meta,
                          num_enabled_secrets):
        assert change_meta.secret_type == "database-api", "Expect secret type to be " \
                                                          "database-api"

        # Get the master secret
        if not self.master_secret:
            assert (
                        "master_secret" in change_meta.config or "DBMASTER_SECRET" in
                        os.environ), "Master secret must be in config key (master_config) or env " \
                                     "variable DBMASTER_SECRET"
            master_secret = change_meta.config[
                "master_secret"] if "master_secret" in change_meta.config else os.environ[
                "DBMASTER_SECRET"]
            self._master_secret = master_secret

        secret_cache = GCPCachedSecret(self.master_secret)
        secret = json.loads(secret_cache.get_secret().decode('utf-8'))
        user = None

        # As this master this allows all configs to pont at same file
        # This is preferred
        if "user" in change_meta.labels:
            user = change_meta.labels["user"]
        elif "user" in change_meta.config:
            # Alternate needs a config file for every user
            user = change_meta.config["user"]
        else:
            user = change_meta.config["initial_secret"]["user"]

        if any(c in self.BLOCKED_CHARACTERS for c in user):
            raise DBPWDInputUnsafe(change_meta.secret_id, user)

        secret_modified = {}
        secret_modified[self._usernamekey] = secret["user"]
        secret_modified[self._passwordkey] = secret["password"]

        # config json structure has properties to allow connection
        # these are merged with secret to create connection properties
        server_connection_properties = {**change_meta.config["server_properties"],
                                        **secret_modified}

        conn_kwargs = server_connection_properties
        conn_args = []
        if "connstring" in change_meta.config:
            conn_kwargs = {}
            conn_args.append(
                change_meta.config["connstring"].format_map(server_connection_properties))

        # we generate a new password
        new_password = self._generate_password()

        change_password = {
            "login_user": user,
            "newpassword": new_password,
        }

        with self.db.connect(*conn_args, **conn_kwargs) as conn:
            with conn.cursor() as curs:
                try:
                    curs.execute(self.statement.format_map(
                        {**server_connection_properties, **change_password}))
                    conn.commit()
                except Exception as e:
                    if type(e).__name__.endswith("ProgrammingError"):
                        logging.getLogger(
                            __name__).exception("While executing {}".format(
                            self.statement.format_map(
                                {**server_connection_properties, **change_password}).replace(
                                secret["password"],
                                "*********")))
                    raise

        new_secret = {"user": user, "password": new_password}
        return new_secret

    def validate_secret(self,
                        rotator,
                        change_meta,
                        num_enabled_secrets):
        return None
