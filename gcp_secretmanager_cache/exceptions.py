# -*- coding: utf-8 -*-

class SecretCacheError(Exception):
    """Base Error class."""


class NoActiveSecretVersion(SecretCacheError):
    CUSTOM_ERROR_MESSAGE = "Secret {} has no active enabled versions"

    def __init__(self, secret):
        super(NoActiveSecretVersion, self).__init__(self.CUSTOM_ERROR_MESSAGE.format(secret))