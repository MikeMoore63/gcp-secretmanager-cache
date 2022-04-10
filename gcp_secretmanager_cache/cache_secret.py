# -*- coding: utf-8 -*-
"""This modules implements the secret cache code

"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import sys
import threading
from datetime import datetime, timedelta
from time import sleep
import weakref

import google.auth
from google.api_core import exceptions
from google.cloud import secretmanager, secretmanager_v1


class SecretCacheError(Exception):
    """Base Error class."""


class NoActiveSecretVersion(SecretCacheError):
    CUSTOM_ERROR_MESSAGE = "Secret {} has no active enabled versions"

    def __init__(self, secret):
        super(NoActiveSecretVersion, self).__init__(self.CUSTOM_ERROR_MESSAGE.format(secret))


SECRET_SURPRESSED_EXCEPTIONS = (exceptions.ServerError,
                                exceptions.TooManyRequests)


# we use a thread disconnected from class to ensure background thread
# references don't keep the class it supports to stay alive beyond its natural lifecycle
def _background_refresh_thread(secret_cache_weak_ref):
    """
    Main background thread driver loop for copying
    :param self: Basis of copy
    :param stop_event: The wevent to stop thread
    :return: None
    """
    # looks like a risk but if weak ref fails will throw exception
    # and kill the thread anyway
    last_run = datetime.utcnow() - timedelta(seconds=secret_cache_weak_ref().ttl)

    # While the object that spawned thread exists
    while secret_cache_weak_ref():
        # each loop grab a reference to the object that spawned thread
        secret_cache = secret_cache_weak_ref()

        # if the object no longer exists exit
        if not secret_cache:
            break

        # the object cannot now go as we have a reference
        try:
            if (datetime.utcnow() - last_run).seconds >= secret_cache.ttl:
                secret = secret_cache._get_secret()
                # make the lock as short as possible
                # largely single thread does this
                # there is a small chance constructor and get
                # might be faster why get_secret doe snot used shared object.
                if secret:
                    with secret_cache.lock:
                        secret_cache.secret = secret
                        secret_cache.exception = None
                last_run = datetime.utcnow()
                # proactively delete referennce
                # So object can be garbage collected during sleep
        except Exception as e:
            logging.getLogger(__name__).exception(f"While refreshing secret {secret_cache.secret_name}")
        del secret_cache
        sleep(0.2)


class GCPCachedSecret():

    def __init__(self, secret_name, _credentials_callback=None, ttl=60.0):
        self._project_id = None
        self._credentials_callback = None
        self.secret = None
        self.exception = None
        self.lock = threading.Lock()
        self._secret_name = secret_name
        self.ns = threading.local()
        self.ttl = ttl

        if _credentials_callback is not None:
            self._credentials_callback = _credentials_callback
        t = threading.Thread(target=_background_refresh_thread,
                             name=f"refresh_secret_{secret_name}", args=[weakref.ref(self)])
        t.daemon = True
        t.start()
        self.t = weakref.ref(t)

    @property
    def _credentials(self):
        if not hasattr(self.ns, "_credentials"):
            if self._credentials_callback is not None:
                _credentials, _project_id = self._credentials_callback()
            else:
                _credentials, _project_id = google.auth.default()
            self.ns._credentials = _credentials
        return self.ns._credentials

    def _client(self):
        if not hasattr(self.ns, "client"):
            self.ns.client = secretmanager.SecretManagerServiceClient(credentials=self._credentials)
        return self.ns.client

    @property
    def secret_name(self):
        return self._secret_name

    def get_secret(self):

        with self.lock:
            secret = self.secret
            if not secret:
                secret = self._get_secret()
                self.secret = secret
                if self.exception:
                    raise self.exception[1]
            # if we have a secret certin exceptions related to
            # server errors or rate limits are surpresses
            # as retries should resolve these in background thread
            # we handle exceptions like this as might be raised
            # in thread that called this or happened asynchronously
            # this looks to try and make errors appear as if the call
            # Was synchronous
            if not secret or (self.exception and isinstance(self.exception, tuple) and
                              not isinstance(self.exception[1], SECRET_SURPRESSED_EXCEPTIONS)):
                self.secret = None
                raise self.exception[1]

        return secret

    def _get_secret(self):

        try:
            secret = None
            request = secretmanager_v1.ListSecretVersionsRequest(
                parent=self.secret_name,
                filter="state=ENABLED"
            )
            page_result = self._client().list_secret_versions(request=request)
            latest = None
            for response in page_result:
                if (latest is None or latest.create_time < response.create_time):
                    latest = response

            if not latest:
                raise NoActiveSecretVersion(self._secret_name)

            request = secretmanager_v1.AccessSecretVersionRequest(
                name=latest.name
            )

            secret = self._client().access_secret_version(request).payload.data

            return secret

        except Exception as e:
            self.exception = sys.exc_info()

        return secret

    def invalidate_secret(self):

        with self.lock:
            self.secret = None
