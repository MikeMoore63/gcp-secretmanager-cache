
"""Decorators for use with gcp secret caching library """
import json

from gcp_secretmanager_cache import GCPCachedSecret

class InjectSecretString:
    """Decorator implementing high-level Secrets Manager caching client"""

    def __init__(self, secret_id, ttl=60, encoding="UTF-8"):
        """
        Constructs a decorator to inject a single non-keyworded argument from a cached secret for a given function.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type ttl: int
        :param ttl: Time to live of secret in seconds

        :type encoding: string
        :param encoding: Character encoding of secret if none is passed as binary default is UTF-8
        """

        self.cache = GCPCachedSecret(secret_name=secret_id,ttl=ttl)
        self.encoding = encoding

    def __call__(self, func):
        """
        Return a function with cached secret injected as first argument.

        :type func: object
        :param func: The function for injecting a single non-keyworded argument too.
        :return The function with the injected argument.
        """
        secret = self.cache.get_secret()
        if self.encoding:
            secret = secret.decode(self.encoding)

        def _wrapped_func(*args, **kwargs):
            """
            Internal function to execute wrapped function
            """
            return func(secret, *args, **kwargs)

        return _wrapped_func


class InjectKeywordedSecretString:
    """Decorator implementing high-level Secrets Manager caching client using JSON-based secrets"""

    def __init__(self, secret_id, ttl=60, **kwargs):
        """
        Construct a decorator to inject a variable list of keyword arguments to a given function with resolved values
        from a cached secret.

        :type kwargs: dict
        :param kwargs: dictionary mapping original keyword argument of wrapped function to JSON-encoded secret key

        :type secret_id: str
        :param secret_id: The secret identifier

        :type cache: gcp_secretamnager_cache.GCPCachedSecret

        """

        self.cache = GCPCachedSecret(secret_name=secret_id,ttl=ttl)
        self.kwarg_map = kwargs
        self.secret_id = secret_id

    def __call__(self, func):
        """
        Return a function with injected keyword arguments from a cached secret.

        :type func: object
        :param func: function for injecting keyword arguments.
        :return The original function with injected keyword arguments
        """

        try:
            secret = json.loads(self.cache.get_secret())
        except json.decoder.JSONDecodeError:
            raise RuntimeError('Cached secret is not valid JSON') from None

        resolved_kwargs = dict()
        for orig_kwarg in self.kwarg_map:
            secret_key = self.kwarg_map[orig_kwarg]
            try:
                resolved_kwargs[orig_kwarg] = secret[secret_key]
            except KeyError:
                raise RuntimeError('Cached secret does not contain key {0}'.format(secret_key)) from None

        def _wrapped_func(*args, **kwargs):
            """
            Internal function to execute wrapped function
            """
            return func(*args, **resolved_kwargs, **kwargs)

        return _wrapped_func
