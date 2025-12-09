This is a simple cache that wraps google cloud platform secrets.
The idea is that when you ask for a secret you can provide a time to live (TTL).
The secret value is fetched once (it supports many threads accessing the same secret cache object). A background thread wakes up at TTL time and refreshes latest secret. If secret service is down it will keep the old secret and retry again and replace the secret as soon as background succeeds.
You pass in a secret name not a version. To fetch a secret takes at least 2 api calls list secret versions and the latest "Enabled" secret is used. This then allows a secret manager to add a new secret and then after the known TTL has passed allow the previous version to be disabled and then deleted.

This then allows a process in background to interact with secret manager to update secret behind the scenes. Enable and disable versions and bar the potential TTL it is forced to renew.
There is also ways to destroy the secret cache if the client wants to proactively renew a secret.

There is background thread that runs for every secret that at TTL fetches the secret in the background. The threads sleep for ttl and only wake to do work at that time including exiting. So the design is not for many of these objects to be short lived on the stack.

The aim of it is to offload complexity and logic of api calls to cache and manage secrets and avoid API overheads in a reasonable way yet still keep secrets very usable. Especially for highly concurrent applications.

There are issues that can occur such as versions being disabled. Or not existing in the first place. It always returns the latest enabled version.

Usage
```python
from gcp_secretmanager_cache import GCPCachedSecret, NoActiveSecretVersion
from google.api_core import exceptions
from time import sleep

# Create a secrets cache safe to share across threads 
# 
bar_secret_cache = GCPCachedSecret("projects/foo/secrets/bar",ttl=60.0)

# Find a secret 
secret1 = bar_secret_cache.get_secret()

# for a secret invalidate it from the cache
bar_secret_cache.invalidate_secret()

# re fetch  the secret from secret manager for sure
secret1 = bar_secret_cache.get_secret()

# do some business logic
# background thread rereads secret after 60 seconds
sleep(120.0)

# now recheck the secret
secret1 = bar_secret_cache.get_secret()

# if all secret versions are disabled or no versions exist
# This happens on initial call or later  calls if secret is
# Disabled
try:
    secret1 = bar_secret_cache.get_secret()
# Note normal exceptions are passed to client thread
# Only serverside errors and quota errors are suppressed as deemed a retry may resolve these
except exceptions.NotFound:
    print("The secret the versions where in does not exist or has been deleted")
except NoActiveSecretVersion:
    print("Secret exists but no enabled secret versions")


```

#### Decorators
The library also includes several decorator functions to wrap existing function calls with SecretString-based secrets:
* `@InjectedKeywordedSecretString` - This decorator expects the secret id  as the first argument, with subsequent arguments mapping a parameter key from the function that is being wrapped to a key in the secret.  The secret being retrieved from the cache must contain a SecretString and that string must be JSON-based. The keys of the json object are used as basis of mapping to the keyword arguments.
* `@InjectSecretString` - This decorator also expects the secret id as the first argument.  However, this decorator simply returns the result of the cache lookup directly to the first argument of the wrapped function.  The secret does not need to be JSON-based but it must contain a SecretString.
```python
from gcp_secretmanager_cache import InjectKeywordedSecretString, InjectSecretString


@InjectKeywordedSecretString(secret_id='projects/foo/secrets/mysecret', func_username='username', func_password='password')
def function_to_be_decorated(func_username, func_password):
    print('Something cool is being done with the func_username and func_password arguments here')
    ...

@InjectSecretString('projects/foo/secrets/mysimplesecret')
def function_to_be_decorated(arg1, arg2, arg3):
    # arg1 contains the cache lookup result of the 'mysimplesecret' secret.
    # arg2 and arg3, in this example, must still be passed when calling function_to_be_decorated().
```
The library also provides mechanisms to handle secret rotation based upon pubsub events triggered by secret rotation events.
It provides a base framework that orchestrates (SecretRotator class) the creation of new secrets and manages the mechanic of enabling an disabling and deleting versions in secret manager. For each type of secret a "mechanic" (a sub class of SecretRotatorMechanic) for managing the secret material needs to be provided.

The library offers an abstract mechanic for adding as basis of new concrete secret management mechanics. Plus concrete implemntations. See table below for details of concrete implementations. The mechanics are designed to be configurable. For example, a database password mechanic might need to know the username, server address, and port, while an API key mechanic might need specific restrictions or annotations.

This configuration can be provided in two ways:

1.  **Via Secret Annotations (Recommended for smaller configs):** A `config` annotation can be added to the secret, containing a JSON string with the necessary configuration. This is simpler as it doesn't require a separate GCS object.
2.  **Via a GCS Object (For larger or shared configs):** The configuration can be stored in a JSON file in a Google Cloud Storage bucket. The secret must then have `config_bucket` and `config_object` labels pointing to this file.

In both cases, a `secret_type` label is required to identify which mechanic to use. The rotator will first look for the `config` annotation and use it if present. If not, it will fall back to looking for the GCS object labels.

Here is an example of the required `secret_type` label and the GCS-based configuration labels. Note that labels have character and length restrictions.
```json
{
  "secret_type": "enum (Secret Type)",
  "config_bucket": "string", # The bucket that the confg blob is stored in
  "config_object": "string"  # The object name in the bucket holding json utf-8 encoded config        
}
```

**Annotations Example**: If your configuration is small you can store it directly
in the secret as an annotation. The rotator looks for an annotation named
`config` (which must be a JSON string) and will parse that as the configuration.

Example: create a secret with a `config` annotation that contains JSON for the
rotator (this example is for a service-account-key rotator that needs the
service account resource name):
```python
import json
from datetime import datetime, timedelta, timezone
from google.cloud import secretmanager, secretmanager_v1

client = secretmanager.SecretManagerServiceClient()
parent = "projects/your-project-id"
secret_id = "MY_SAKEY_ROTATION"

config = json.dumps({
    "name": "projects/your-project-id/serviceAccounts/my-sa@your-project-id.iam.gserviceaccount.com"
})

client.create_secret(
    request={
        "parent": parent,
        "secret_id": secret_id,
        "secret": {
            "replication": {"automatic": {}},
            "labels": {"secret_type": "google-serviceaccount"},
            "annotations": {"config": config},
            "rotation": {
                "rotation_period": timedelta(seconds=3600),
                "next_rotation_time": datetime.now(timezone.utc) + timedelta(seconds=3600),
            },
            "topics": [secretmanager_v1.Topic(name="projects/your-project-id/topics/secretrotate")],
        },
    }
)
```

Notes:
- The annotation value must be a JSON string (use `json.dumps(...)`).
- The rotator prefers the `config` annotation; if not present it will fall
  back to `config_bucket`/`config_object` labels that point to a GCS JSON blob.

The concrete implemntations of secret rotators are documented below. For these to work the approriate roles MUST be granted to the process to be able to do its job.

|secret_type| Mechanic Class                     | What it manages the secret of                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|-----------|------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|google-apikey| APIKeyRotator                      | Manages creation of new google api keys                                                                                                                                                                                                                                                                                                                                                                                                                        |
|google-serviceaccount| SAKeyRotator                       | Manages creation of service account keys for a google servce accounts                                                                                                                                                                                                                                                                                                                                                                                          |
|database-api| DBApiSingleUserPasswordRotator or DBApiMasterUserPasswordRotator | Manages password rotation of a single user account. Logs in as that user changes password and updates secret. The class DBApiSingleUserPasswordRotatorConstants has constants for various popular databases. See tests in source code for examples with Postgres, MySQL and MSSQL. The alternate mechanism DBApiMasterUserPasswordRotator works in a similar way but is in addition provided a secret to get a master user that can change any users password. |

Example code for the api key rotator below.

Create a config blob
```python
import json
from google.cloud import storage

client = storage.Client()
bucket = client.get_bucket("secret_config_bucket")
blob = bucket.blob("apikey-template")

# the api key rotator MUST have displayName as it uses that to link related apikeys
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
```

Create a secret that is for apikeys that has a rotation policy. the topics and subscriptions for the rotation MUST be also setup as normal for pubsub.

```python
import pytz
from datetime import datetime, timedelta,timezone
from google.cloud import secretmanager, secretmanager_v1
client = secretmanager.SecretManagerServiceClient()
parent = "projects/demo-secret-rotation"
secret_id = "DEMO_APIKEY_ROTATION_FRAMEWORKS"

# create rotating secrets with labels required for rotator i.e. secret_type
# and config_bucket and config_object pointing at template api key
client.create_secret(
    request={
        "parent": parent,
        "secret_id": secret_id,
        "secret": {
            "replication":
                {"automatic": {}
                 },
            "labels": {
                "secret_type": "google-apikey",
                "config_bucket": "secret_config_bucket",
                "config_object": "apikey-template"
            },
            "rotation": {
                "rotation_period": timedelta(seconds=3600),
                "next_rotation_time": datetime.now(timezone.utc) + timedelta(seconds=3600),
            },
            "topics": [
                secretmanager_v1.Topic(name="projects/demo-secret-rotation/topics/secretrotate")
            ]
        }
    }
)
```
Then to implement secret rotation for the apikey in a python program that processes the event could be cloud function or cloud run or any other context for execution of pubsub.
```python
from gcp_secretmanager_cache import APIKeyRotator, SecretRotator

# create the rotator mechanism passing in constructor which mechanic to use
rotator_mechanism = SecretRotator(APIKeyRotator())
...

# in the call back o fthe pubsub event call the rotator mechanic
# This leverages the data passed in a secret rotation event
# https://cloud.google.com/secret-manager/docs/event-notifications
rotator_mechanism.rotate_secret(message_attributes, data)
```
