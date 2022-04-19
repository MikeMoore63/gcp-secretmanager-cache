# -*- coding: utf-8 -*-

class SecretCacheError(Exception):
    """Base Error class."""


class NoActiveSecretVersion(SecretCacheError):
    CUSTOM_ERROR_MESSAGE = "Secret {} has no active enabled versions"

    def __init__(self, secret):
        super(NoActiveSecretVersion, self).__init__(self.CUSTOM_ERROR_MESSAGE.format(secret))

class SecretRotatorError(Exception):
    """Base Error class."""


class DBPWDInputUnsafe(SecretRotatorError):
    CUSTOM_ERROR_MESSAGE = "Database Secret {} has Username {} or password have characters not allowed ['\" ;]"
    def __init__(self, secret_id, username):
        super(DBINputUnsafe, self).__init__(self.CUSTOM_ERROR_MESSAGE.format(secret_id, username))

class NewSecretCreateError(SecretRotatorError):
    CUSTOM_ERROR_MESSAGE = "Secret {} rotation failed {} error {}"

    def __init__(self, secret_id, request_body, error):
        super(NewSecretCreateError, self).__init__(self.CUSTOM_ERROR_MESSAGE.format(secret_id,
                                                                                    str(request_body),
                                                                                    str(error)))
        self._error = error
        self._request_body = request_body
        self._secret_id = secret_id

    @property
    def error(self):
        return self._error

    @property
    def request_body(self):
        return self._request_body

    @property
    def secret_id(self):
        return self._secret_id