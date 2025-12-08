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
from datetime import datetime, timedelta, timezone

import google.auth
import google_crc32c
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
                                         # manage the secret. We do this as data stored in labels
                                         # is limited. Each concrete implementation describes what
                                         # should be in the config object.
                                         # be aware "/" and "." not allowed in label value.
                                         # The blob of config is expected to be utf-8 encoded json
                                         # if one of these is set it is expected the other MUST
                                         # be as well
}

secret_type ENUMS

test-rotation     Used in gcp_secretmanager_cache tests
google-apikey     Used to indicate that the secret is an api key string

Now that annotations 
"""


@dataclass
class ChangeSecretMeta:
    secret_type: str
    config: dict
    labels: dict
    annotations: dict
    secret_resource: dict
    secret_id: str
    rotation_period_seconds: int
    ttl: int

    @property
    def disable_oldest_time(self):
        return datetime.now(timezone.utc) - timedelta(
            seconds=int(self.rotation_period_seconds * 1.5)
        )

    @property
    def delete_oldest_time(self):
        return datetime.now(timezone.utc) - timedelta(
            seconds=int(self.rotation_period_seconds * 5)
        )

    @property
    def project_id(self):
        return re.search(r"projects/([^/]+)", self.secret_id).group(1)


class SecretRotatorMechanic(ABC):
    """Abstract Base Class for a secret rotation mechanic.

    This class defines the interface for different strategies of secret rotation.
    The `SecretRotator` uses a concrete implementation of this class to perform
    the specific actions required to rotate a secret, such as creating a new
    API key or changing a database password. This follows the strategy pattern,
    where `SecretRotator` is the context and `SecretRotatorMechanic` and its
    subclasses are the strategies.
    """

    @abstractmethod
    def disable_old_secret_versions_material(self, rotator, change_meta, event):
        """
        Abstract method but is used to drive any expiry of old material
        Handles the disabling or deletion of the old secret material.

        This abstract method is responsible for any logic needed to invalidate
        the actual old secret (e.g., deleting an old API key from the provider,
        not just the secret version in Secret Manager). It can be called before
        or after the main rotation logic.

        Args:
            rotator (SecretRotator): The rotator instance calling this method.
            change_meta (ChangeSecretMeta): Metadata about the secret being rotated.
            event (str): The rotation event, e.g., "PreRotate" or "PostRotate".
        """
        pass

    @abstractmethod
    def create_new_secret(self, rotator, change_meta, num_enabled_secrets):
        """Creates the new secret material.

        This method contains the logic to generate a new secret, for example,
        by calling a cloud provider's API to create a new key or by generating
        a new password and updating it in a database.

        Args:
            rotator (SecretRotator): The rotator instance calling this method.
            change_meta (ChangeSecretMeta): Metadata about the secret being rotated.
            num_enabled_secrets (int): The number of currently enabled secret versions.

        Returns:
            The new secret material. The format depends on the implementation
            (e.g., a string, a dictionary). This will be stored as the new
            secret version.
        """
        return None

    def validate_secret(self, rotator, change_meta, num_enabled_secrets):
        """Validates that the newly created secret is functional.

        This is an optional method to implement. It can be used to perform checks
        to ensure the new secret material is working as expected before the
        rotation process completes. If validation fails, it should raise an
        exception.
        """
        return None


class SecretRotator:
    """Orchestrates the secret rotation process based on GCP Secret Manager events.

    This class acts as the "Context" in a strategy pattern. It is responsible for
    handling the generic workflow of a secret rotation triggered by a Pub/Sub
    notification from Secret Manager. It parses the event, interacts with the
    Secret Manager API to manage secret versions, and delegates the secret-specific
    logic (creating new material, deleting old material) to a `SecretRotatorMechanic`
    instance (the "Strategy").

    It uses thread-local storage (`threading.local`) to maintain thread-safe
    GCP clients and credentials, making it suitable for use in concurrent
    environments like Cloud Functions.

    Attributes:
        mechanic (SecretRotatorMechanic): The strategy for handling the
            secret-specific rotation logic.
        ttl (int): The time-to-live for cached secrets, used in the rotation metadata.
    """

    def __init__(
        self,
        mechanic,
        ttl=60,
        _credentials_callback=None,
    ):
        """Initializes the SecretRotator.

        Args:
            mechanic (SecretRotatorMechanic): A concrete implementation of the
                `SecretRotatorMechanic` that defines the specific rotation logic.
            ttl (int, optional): The time-to-live for cached secrets. Defaults to 60.
            _credentials_callback (callable, optional): A function that returns a
                tuple of (credentials, project_id). If not provided,
                `google.auth.default()` is used.
        """
        self._ttl = ttl
        self._credentials_callback = _credentials_callback
        self._mechanic = mechanic
        self.ns = threading.local()

    @property
    def ttl(self):
        """The time-to-live for cached secrets."""
        return self._ttl

    @property
    def mechanic(self):
        """The `SecretRotatorMechanic` strategy instance."""
        return self._mechanic

    @property
    def credentials(self):
        """Provides thread-safe GCP credentials.

        Uses the provided `_credentials_callback` or `google.auth.default()`
        to obtain credentials and caches them in thread-local storage.

        Returns:
            google.auth.credentials.Credentials: The GCP credentials.
        """
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
        """Provides a thread-safe Secret Manager service client."""
        if not hasattr(self.ns, "client"):
            self.ns.client = secretmanager.SecretManagerServiceClient(
                credentials=self.credentials
            )
        return self.ns.client

    @property
    def project_id(self):
        """The GCP project ID associated with the credentials."""
        if not hasattr(self.ns, "_project_id"):
            # This triggers the credentials property to populate the project_id
            _ = self.credentials
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

        Args:
            attributes (dict): The attributes of the Pub/Sub message. Expected to
                contain `eventType` and `secretId`.
            data (bytes): The data payload of the Pub/Sub message, containing
                metadata about the secret in JSON format.
        """
        data = json.loads(data.decode("utf-8"))
        if (
            attributes["eventType"] != "SECRET_ROTATE"
            or "secretId" not in attributes
            or "labels" not in data
            or "secret_type" not in data["labels"]
        ):
            logging.getLogger(__name__).warning(
                f"Received event that does not meet predicates for secret rotation attributes:"
                f"{json.dumps(attributes)}, data:{json.dumps(data)}"
            )
            return

        config = None
        if "annotations" in data and "config" in data["annotations"]:
            config = json.loads(data["annotations"]["config"])
        if (
            not config
            and "config_bucket" in data["labels"]
            and "config_object" in data["labels"]
        ):
            config = self.load_config(
                data["labels"]["config_bucket"], data["labels"]["config_object"]
            )

        # construct change_meta holds data for context for all helpers during change
        # roles/secretmanager.secretVersionManager does not have ability to read secret this is
        # passed
        # The ChangesSecretMeta holds meta data for a secret change
        # we have one of these as many threads maybe being run in parallel
        # passing as an object on stack avoids locks and more complex
        # threading constructs
        change_meta = ChangeSecretMeta(
            secret_type=data["labels"]["secret_type"],
            labels=data["labels"],
            annotations=data.get("annotations", {}),
            config=config,
            secret_resource=data,
            secret_id=attributes["secretId"],
            rotation_period_seconds=int(data["rotation"]["rotationPeriod"][:-1]),
            ttl=self.ttl,
        )

        # This is opportunity for concrete class to delete unused
        # secret material if any
        self.mechanic.disable_old_secret_versions_material(
            self, change_meta, event="PreRotate"
        )

        # Mechanic to disable the secret versions in secrete manager
        num_enabled_secrets = self.disable_old_secret_versions(change_meta)

        # Call back to create a new secret based on secret
        # config in some cases may even create an initial secret
        secret = self.mechanic.create_new_secret(self, change_meta, num_enabled_secrets)

        # Any test to validate secret is setup correctly
        # Optional to implement should throw exception if fails
        self.mechanic.validate_secret(self, change_meta, secret)

        # Now add the secret version
        # stores the secret as a new version
        self.add_new_version(change_meta, secret)

        # Call back to invalidate old secrets if disable_old_secrets
        # not sufficient.
        # This is second chance to invalidate secrets but
        self.mechanic.disable_old_secret_versions_material(
            self, change_meta, event="PostRotate"
        )

    def load_config(self, bucket, blob_name):
        """Loads a JSON configuration file from Google Cloud Storage.

        Args:
            bucket (str): The name of the GCS bucket.
            blob_name (str): The name of the object (file) in the bucket.

        Returns:
            dict: The parsed JSON configuration.
        """
        client = storage.Client(credentials=self.credentials)
        bucket = client.get_bucket(bucket)
        blob = bucket.get_blob(blob_name)
        return json.loads(blob.download_as_bytes().decode("utf-8"))

    def disable_old_secret_versions(self, change_meta):
        """Disables and destroys old secret versions in Secret Manager.

        This method lists all versions of a secret, disables versions that are
        older than the configured rotation period, and destroys versions that
        are significantly older.

        Args:
            change_meta (ChangeSecretMeta): Metadata about the secret being rotated.
        """
        min_age = change_meta.disable_oldest_time

        request = secretmanager_v1.ListSecretVersionsRequest(
            parent=change_meta.secret_id, filter="state!=DESTROYED"
        )
        page_result = self._client.list_secret_versions(request=request)
        to_disable = []
        to_delete = []
        previous = None

        # Assume 1
        num_active = 1
        num_iter = 0
        for num_iter, response in enumerate(
            sorted(page_result, key=lambda d: d.create_time)
        ):
            # if set was the previous one
            # we do this to avoid disabling th elatest
            if (
                previous
                and response.state == secretmanager_v1.SecretVersion.State.ENABLED
            ):
                to_disable.append(previous)

            if (
                response.state == secretmanager_v1.SecretVersion.State.DISABLED
                and response.create_time < change_meta.delete_oldest_time
            ):
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
            self._client.disable_secret_version(name=disable.name)

        for delete in to_delete:
            self._client.destroy_secret_version(name=delete.name)

        return num_active

    def add_new_version(self, change_meta, secret):
        """Adds a new version of the secret to Secret Manager.

        The new secret payload is encoded, its checksum is calculated, and it's
        added as the latest version for the specified secret.

        Args:
            change_meta (ChangeSecretMeta): Metadata about the secret being rotated.
            secret (Any): The new secret material. It will be converted to a
                UTF-8 encoded byte string.

        Returns:
            google.cloud.secretmanager_v1.types.SecretVersion: The response from the API.
        """
        # Convert the string payload into a bytes. This step can be omitted if you
        # pass in bytes instead of a str for the payload argument.
        if not isinstance(secret, bytes):
            if isinstance(secret, dict) or isinstance(secret, list):
                secret = json.dumps(secret)
            if not isinstance(secret, str):
                secret = str(secret)
            secret = secret.encode("utf8")

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
    """A `SecretRotatorMechanic` for rotating Google Cloud API Keys.

    This class implements the logic for creating new Google Cloud API keys and
    deleting old ones as part of a secret rotation process. It uses the key's
    `displayName` to identify and manage different versions of the same conceptual key.

    The secret's configuration (from annotations or a GCS object) must specify
    the `displayName` and can optionally provide other API key properties like
    `restrictions`.

    **Required `secret_type` label:** `google-apikey`

    **Example Configuration:**
    ```json
    {
        "displayName": "my-application-api-key",
        "parent": "projects/my-gcp-project/locations/global",
        "restrictions": {
            "apiTargets": [{
                "service": "storage.googleapis.com"
            }]
        },
        "annotations": {
            "owner": "my-team"
        }
    }
    ```
    """

    def disable_old_secret_versions_material(self, rotator, change_meta, event):
        """Deletes old API keys from Google Cloud.

        During the "PreRotate" event, this method lists all API keys that share the
        same `displayName` as specified in the configuration. It identifies keys
        older than the `delete_oldest_time` and deletes them using the API Keys API.
        """
        if event != "PreRotate":
            return

        assert (
            change_meta.secret_type == "google-apikey"
        ), "Expect secret type to be google-apikey"

        credentials = rotator.credentials

        assert "displayName" in change_meta.config, (
            "APIKEY config must have a template api key "
            "which must have a displayName"
        )

        apikeys_service = build("apikeys", "v2", credentials=credentials)
        loc_api = apikeys_service.projects().locations().keys()

        parent = f"projects/{change_meta.project_id}/locations/global"
        if "parent" in change_meta.config:
            parent = change_meta.config["parent"]

        psrequest = loc_api.list(parent=parent, pageSize=300)

        to_delete = []
        latest = None
        while psrequest is not None:
            api_key_list_resp = psrequest.execute()
            for api_key in api_key_list_resp.get("keys", []):
                if api_key["displayName"] == change_meta.config["displayName"]:
                    createTime = parser.parse(api_key["createTime"])
                    if not latest or createTime > parser.parse(latest["createTime"]):
                        latest = api_key
                    if createTime < change_meta.delete_oldest_time:
                        to_delete.append(api_key)
                        logging.getLogger(__name__).info(
                            f"Found apikey to delete {json.dumps(api_key)}"
                        )

            if "nextPageToken" in api_key_list_resp:
                psrequest = loc_api.list(
                    parent=parent,
                    pageSize=300,
                    pageToken=api_key_list_resp["nextPageToken"],
                )
            else:
                psrequest = None

        for delete_key in to_delete:
            if delete_key["createTime"] != latest["createTime"]:
                del_req = loc_api.delete(name=delete_key["name"])
                # returns op but we won't wait
                del_req.execute()
                logging.getLogger(__name__).info(f"Deleted apikey {delete_key['name']}")

    def create_new_secret(self, rotator, change_meta, num_enabled_secrets):
        """Creates a new Google Cloud API key.

        This method calls the API Keys API to create a new key based on the
        `displayName`, `restrictions`, and `annotations` in the configuration.
        It waits for the creation operation to complete and then retrieves the
        plaintext key string.

        Returns:
            dict: A dictionary containing the new key's resource `name` and its
                  `keyString`. This dictionary is stored as the new secret version.
        """
        apikeys_service = build("apikeys", "v2", credentials=rotator.credentials)
        loc_api = apikeys_service.projects().locations().keys()
        ops_api = apikeys_service.operations()

        parent = f"projects/{change_meta.project_id}/locations/global"
        if "parent" in change_meta.config:
            parent = change_meta.config["parent"]

        body = {}
        for key in ["restrictions", "displayName", "annotations"]:
            if key in change_meta.config:
                body[key] = change_meta.config[key]

        req_create = loc_api.create(parent=parent, body=body)
        op_response = req_create.execute()
        while not op_response.get("done"):
            op_req = ops_api.get(name=op_response["name"])
            op_response = op_req.execute()

        if "error" in op_response:
            raise NewSecretCreateError(
                change_meta.secret_id, body, op_response["error"]
            )

        # Now we can get the resource created
        apikey_resource = op_response["response"]

        keystring_req = loc_api.getKeyString(name=apikey_resource["name"])
        keystring_object = keystring_req.execute()
        keystring_object["name"] = apikey_resource["name"]
        return keystring_object

    def validate_secret(self, rotator, change_meta, num_enabled_secrets):
        """Validates the newly created API key. This method is not implemented."""
        return None


class SAKeyRotator(SecretRotatorMechanic):
    """A `SecretRotatorMechanic` for rotating Google Cloud Service Account (SA) keys.

    This class implements the logic for creating new service account keys and
    disabling/deleting old ones. It identifies the target service account via its
    full resource name.

    The secret's configuration (from annotations or a GCS object) must specify
    the `name` of the service account for which to rotate keys.

    **Required `secret_type` label:** `google-serviceaccount`

    **Example Configuration:**
    ```json
    {
        "name": "projects/my-gcp-project/serviceAccounts/my-sa@my-gcp-project.iam.gserviceaccount.com"
    }
    ```
    """

    def disable_old_secret_versions_material(self, rotator, change_meta, event):
        """Disables and deletes old service account keys.

        During the "PreRotate" event, this method lists all user-managed keys for
        the specified service account. It disables keys older than the
        `disable_oldest_time` and deletes keys older than the `delete_oldest_time`.
        """
        if event != "PreRotate":
            return

        assert change_meta.secret_type == "google-serviceaccount", (
            "Expect secret type to be " "google-serviceAccount"
        )

        credentials = rotator.credentials

        assert "name" in change_meta.config, (
            "Service Account key rotator config MUST have a name" " key"
        )

        iam_service = build("iam", "v1", credentials=credentials)
        loc_api = iam_service.projects().serviceAccounts().keys()

        psrequest = loc_api.list(
            name=change_meta.config["name"], keyTypes="USER_MANAGED"
        )

        to_disable = []
        to_delete = []
        latest = None

        api_key_list_resp = psrequest.execute()
        for api_key in api_key_list_resp.get("keys", []):
            createTime = parser.parse(api_key["validAfterTime"])
            if not latest or createTime > parser.parse(latest["validAfterTime"]):
                latest = api_key
            if createTime < change_meta.disable_oldest_time and (
                "disabled" not in api_key or not api_key["disabled"]
            ):
                to_disable.append(api_key)
                logging.getLogger(__name__).info(
                    # only get has sensitive data so no risk
                    f"Found api key to disable {json.dumps(api_key)}"
                )

            if createTime < change_meta.delete_oldest_time:
                to_delete.append(api_key)
                logging.getLogger(__name__).info(
                    f"Found api key to delete {json.dumps(api_key)}"
                )

        for disable_key in to_disable:
            if disable_key["validAfterTime"] != latest["validAfterTime"]:
                disable_req = loc_api.disable(name=disable_key["name"])
                # returns op but we won't wait
                disable_req.execute()

        for delete_key in to_delete:
            if delete_key["validAfterTime"] != latest["validAfterTime"]:
                del_req = loc_api.delete(name=delete_key["name"])
                # returns op but we won't wait
                del_req.execute()

    def create_new_secret(self, rotator, change_meta, num_enabled_secrets):
        """Creates a new Google Cloud Service Account key.

        This method calls the IAM API to create a new key of type
        `TYPE_GOOGLE_CREDENTIALS_FILE` for the service account specified in the
        configuration.

        Returns:
            bytes: The new service account key, decoded from base64 into a JSON byte string.
        """
        assert change_meta.secret_type == "google-serviceaccount", (
            "Expect secret type to be " "google-serviceAccount"
        )

        credentials = rotator.credentials

        assert "name" in change_meta.config, (
            "Service Account key rotator config MUST have a name" " key"
        )

        body = {"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"}
        iam_service = build("iam", "v1", credentials=credentials)
        loc_api = iam_service.projects().serviceAccounts().keys()
        sakey_req = loc_api.create(
            name=change_meta.config["name"], alt="json", body=body
        )
        sakey_resp = sakey_req.execute()
        new_key = base64.standard_b64decode(sakey_resp["privateKeyData"])
        return new_key

    def validate_secret(self, rotator, change_meta, num_enabled_secrets):
        """Validates the newly created SA key. This method is not implemented."""
        return None


class DBRotator(SecretRotatorMechanic):
    """Abstract base class for rotating database passwords.

    This class provides common mechanics for `SecretRotatorMechanic`
    implementations that change database passwords using a Python DB-API 2.0
    compliant driver. It handles password generation and holds common
    configuration for database connections.

    Subclasses must implement the `create_new_secret` method to define the
    specific strategy for connecting to the database and executing the password
    change statement.
    """

    BLOCKED_CHARACTERS = ";' \"\\"

    def __init__(
        self,
        db,
        statement,
        exclude_characters=None,
        password_length=20,
        usernamekey=None,
        passwordkey=None,
    ):
        """Initializes the DBRotator.

        Args:
            db: A DB-API 2.0 compliant database module (e.g., psycopg2).
            statement (str): The SQL statement template to execute for changing
                the password. It can use format placeholders like `{user}` and
                `{newpassword}`.
            exclude_characters (str, optional): A string of characters to exclude
                from generated passwords. Defaults to a common set of problematic
                characters.
            password_length (int, optional): The desired length for generated
                passwords. Defaults to 20.
            usernamekey (str, optional): The dictionary key for the username when
                building connection arguments. Defaults to "user".
            passwordkey (str, optional): The dictionary key for the password when
                building connection arguments. Defaults to "password".
        """
        super(DBRotator, self).__init__()
        if not usernamekey:
            usernamekey = "user"
        if not passwordkey:
            passwordkey = "password"

        if not exclude_characters:
            exclude_characters = " ,'\"\\+=%^*~[].{}@&"
        self._db = db
        self._statement = statement
        self._exclude_characters = exclude_characters
        self._password_length = password_length
        self._usernamekey = usernamekey
        self._passwordkey = passwordkey

    def _generate_password(self):
        """Generates a cryptographically secure random password.

        The password consists of ASCII letters and digits, excluding any
        characters specified in `_exclude_characters`.

        Returns:
            str: The newly generated password.
        """
        letters = string.ascii_letters + string.digits
        password = ""
        while len(password) < self._password_length:
            candidate = secrets.choice(letters)
            if (
                not self._exclude_characters
                or candidate not in self._exclude_characters
            ):
                password = password + candidate
        return password

    @property
    def db(self):
        """The DB-API 2.0 module used for creating connections."""
        return self._db

    @property
    def statement(self):
        """The SQL statement template for changing the password."""
        return self._statement


class DBApiSingleUserPasswordRotatorConstants:
    """Provides a collection of common SQL statements for password rotation.

    These statement templates are designed for the "single user" rotation
    strategy, where the user connects to the database and changes their own
    password. They can be passed to the `DBApiSingleUserPasswordRotator`
    constructor.

    The templates may use the following format placeholders:
    - `{user}`: The username.
    - `{password}`: The current password (used by MSSQL).
    - `{newpassword}`: The new password to be set.
    """

    PG = "ALTER USER {user} WITH PASSWORD '{newpassword}';"
    MARIADB = "SET PASSWORD = PASSWORD('{newpassword}');"
    MYSQL = "SET PASSWORD = PASSWORD('{newpassword}');"
    ORACLE = 'ALTER USER {user} IDENTIFIED BY "{newpassword}"'
    SYBSASE = "sp_password {password}, {newpassword}"
    MSSQL = "ALTER LOGIN {user} WITH PASSWORD = '{newpassword}' OLD_PASSWORD = '{password}';"


class DBApiSingleUserPasswordRotator(DBRotator):
    """A `DBRotator` for changing a database password using the user's own credentials.

    This class implements the "single user" rotation strategy. It connects to the
    database using the user's current password to execute a statement that changes
    that same user's password.

    It requires access to the current secret to establish the initial connection.
    On the very first rotation (when no secret versions exist), it can use an
    `initial_secret` defined in the configuration.

    **Required `secret_type` label:** `database-api`

    **Secret Format:**
    The secret stored in Secret Manager must be a JSON object with `user` and
    `password` keys.
    ```json
    {
        "user": "my-db-user",
        "password": "the-current-password"
    }
    ```

    **Example Configuration:**
    ```json
    {
        "server_properties": {
            "host": "127.0.0.1",
            "port": 5432,
            "dbname": "mydb"
        },
        "initial_secret": {
            "user": "my-db-user",
            "password": "the-bootstrap-password"
        }
    }
    ```
    """

    def disable_old_secret_versions_material(self, rotator, change_meta, event):
        """A placeholder method that asserts the secret type. No material is disabled."""
        if event != "PreRotate":
            return
        assert change_meta.secret_type == "database-api", "Expect database api"

    def create_new_secret(self, rotator, change_meta, num_enabled_secrets):
        assert change_meta.secret_type == "database-api", (
            "Expect secret type to be " "database-api"
        )

        """Creates a new secret by changing the user's own database password.

        This method performs the following steps:
        1. Fetches the current secret (username and password) from the latest
           enabled version in Secret Manager. If no version exists, it falls
           back to the `initial_secret` from the configuration.
        2. Generates a new cryptographically secure password.
        3. Builds the connection arguments using the `server_properties` from the
           configuration and the current user credentials.
        4. Connects to the database.
        5. Executes the password change SQL statement.
        6. Returns the new secret payload containing the username and the new password.

        Returns:
            dict: A dictionary with `user` and `password` keys for the new secret.
        """
        # Get the existing secret if it has a version
        secret_cache = GCPCachedSecret(change_meta.secret_id)

        try:
            secret = json.loads(secret_cache.get_secret().decode("utf-8"))
        # if we get no active version we use the initial secret
        except NoActiveSecretVersion:
            secret = change_meta.config["initial_secret"]
            if any(c in self.BLOCKED_CHARACTERS for c in secret["user"]) or any(
                c in self.BLOCKED_CHARACTERS for c in secret["password"]
            ):
                raise DBPWDInputUnsafe(change_meta.secret_id, secret["user"])

        secret_modified = {}
        secret_modified[self._usernamekey] = secret["user"]
        secret_modified[self._passwordkey] = secret["password"]

        # config json structure has properties to allow connection
        # these are merged with secret to create connection properties
        server_connection_properties = {
            **change_meta.config["server_properties"],
            **secret_modified,
        }

        conn_kwargs = server_connection_properties
        conn_args = []
        if "connstring" in change_meta.config:
            conn_kwargs = {}
            conn_args.append(
                change_meta.config["connstring"].format_map(
                    server_connection_properties
                )
            )

        # we generate a new password
        new_password = self._generate_password()

        with self.db.connect(*conn_args, **conn_kwargs) as conn:
            with conn.cursor() as curs:
                try:
                    curs.execute(
                        self.statement.format_map(
                            {
                                **server_connection_properties,
                                **{"newpassword": new_password},
                            }
                        )
                    )
                    conn.commit()
                except Exception as e:
                    if type(e).__name__.endswith("ProgrammingError"):
                        logging.getLogger(__name__).exception(
                            "While executing {}".format(
                                self.statement.format_map(
                                    {
                                        **server_connection_properties,
                                        **{"newpassword": new_password},
                                    }
                                ).replace(secret["password"], "*********")
                            )
                        )
                    raise

        new_secret = {"user": secret["user"], "password": new_password}
        return new_secret

    def validate_secret(self, rotator, change_meta, num_enabled_secrets):
        """Validates the new secret. This method is not implemented."""
        return None


class DBApiMasterUserPasswordRotatorConstants:
    """Provides a collection of common SQL statements for master user password rotation.

    These statement templates are designed for the "master user" rotation
    strategy, where a privileged master user connects to the database to change
    the password of another, less-privileged user. They can be passed to the
    `DBApiMasterUserPasswordRotator` constructor.

    The templates may use the following format placeholders:
    - `{login_user}`: The user whose password is being changed.
    - `{newpassword}`: The new password to be set.
    - `{password}`: The master user's current password (used by some database
      systems like Sybase in their password change statements).
    """

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

    def __init__(
        self,
        db,
        statement,
        exclude_characters=None,
        password_length=16,
        usernamekey=None,
        passwordkey=None,
        master_secret=None,
    ):
        super(DBApiMasterUserPasswordRotator, self).__init__(
            db, statement, exclude_characters, password_length, usernamekey, passwordkey
        )
        self._master_secret = master_secret

    @property
    def master_secret(self):
        return self._master_secret

    def disable_old_secret_versions_material(self, rotator, change_meta, event):

        if event != "PreRotate":
            return

        assert (
            change_meta.secret_type == "database-api"
        ), "Expect database-api as secret_type"

    def create_new_secret(self, rotator, change_meta, num_enabled_secrets):
        assert change_meta.secret_type == "database-api", (
            "Expect secret type to be " "database-api"
        )

        # Get the master secret
        if not self.master_secret:
            assert (
                "master_secret" in change_meta.config or "DBMASTER_SECRET" in os.environ
            ), (
                "Master secret must be in config key (master_config) or env "
                "variable DBMASTER_SECRET"
            )
            master_secret = (
                change_meta.config["master_secret"]
                if "master_secret" in change_meta.config
                else os.environ["DBMASTER_SECRET"]
            )
            self._master_secret = master_secret

        secret_cache = GCPCachedSecret(self.master_secret)
        secret = json.loads(secret_cache.get_secret().decode("utf-8"))
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
        server_connection_properties = {
            **change_meta.config["server_properties"],
            **secret_modified,
        }

        conn_kwargs = server_connection_properties
        conn_args = []
        if "connstring" in change_meta.config:
            conn_kwargs = {}
            conn_args.append(
                change_meta.config["connstring"].format_map(
                    server_connection_properties
                )
            )

        # we generate a new password
        new_password = self._generate_password()

        change_password = {
            "login_user": user,
            "newpassword": new_password,
        }

        with self.db.connect(*conn_args, **conn_kwargs) as conn:
            with conn.cursor() as curs:
                try:
                    curs.execute(
                        self.statement.format_map(
                            {**server_connection_properties, **change_password}
                        )
                    )
                    conn.commit()
                except Exception as e:
                    if type(e).__name__.endswith("ProgrammingError"):
                        logging.getLogger(__name__).exception(
                            "While executing {}".format(
                                self.statement.format_map(
                                    {**server_connection_properties, **change_password}
                                ).replace(secret["password"], "*********")
                            )
                        )
                    raise

        new_secret = {"user": user, "password": new_password}
        return new_secret

    def validate_secret(self, rotator, change_meta, num_enabled_secrets):
        return None
