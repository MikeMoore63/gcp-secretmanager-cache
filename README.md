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