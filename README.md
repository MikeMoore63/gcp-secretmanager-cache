This is a simple cache that wraps google cloud platform secrets.
The idea is that when you ask for a secret you can provide a time to live (TTL).
The secret value is fetched but when a call happens above the time to live the secret is pulled again and latest version is used.
You pass in a secret name not a version. To fetch a secret takes at least 2 api calls list secret versions and the latest "Enabled" secret is used. This then allows a secret manager to add a new secret and then after the known TTL has passed allow the previous version to be disabled and then deleted.

This then allows a secret manager to update secret behind the scenes. Enable and disable versions and bar the potential TTL it is forced to renew.
There is also ways to destroy the secret cache if the client wants to proactively renew a secret.

There is background thread that runs for every secret that at TTL fetches the secret in teh background.

The aim of it is to offload complexity and logic of api calls to cache and manage secrets and avoid API overheads in a reasonable way yet still keep secrets very usable. Especially for highly concurrent applications.


Usage
```angular2html
from gcp_secretmanager_cache import GCPCachedSecret

# Create a secrets cache safe to share across threads 
# 
bar_secret_cache = GCPCachedSecret("bar",ttl=60.0)

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

```