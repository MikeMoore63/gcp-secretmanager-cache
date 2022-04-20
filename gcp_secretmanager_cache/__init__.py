# -*- coding: utf-8 -*-
"""gcp_secretmanager_cache

Some utilities to cache GCP secrets with a bit of intelligence and manage when they rotate and
trades off reliability, usability, predictability and performance vs accuracy and timeliness

"""

from __future__ import absolute_import

from gcp_secretmanager_cache.cache_secret import GCPCachedSecret
from gcp_secretmanager_cache.exceptions import NoActiveSecretVersion, \
    SecretCacheError, \
    NewSecretCreateError, \
    SecretRotatorError, \
    DBPWDInputUnsafe
from gcp_secretmanager_cache.decorators import InjectKeywordedSecretString, InjectSecretString
from gcp_secretmanager_cache.managers import SecretRotator, \
    SecretRotatorMechanic, \
    ChangeSecretMeta, \
    APIKeyRotator, \
    SAKeyRotator, \
    DBApiSingleUserPasswordRotatorConstants, \
    DBApiSingleUserPasswordRotator, \
    DBApiMasterUserPasswordRotatorConstants, \
    DBApiMasterUserPasswordRotator
from ._version import __version__

__all__ = ["__version__",
           "NoActiveSecretVersion",
           "GCPCachedSecret",
           "InjectSecretString",
           "SecretCacheError",
           "InjectKeywordedSecretString",
           "SecretRotator",
           "SecretRotatorMechanic",
           "ChangeSecretMeta",
           "NewSecretCreateError",
           "SecretRotatorError",
           "APIKeyRotator",
           "SAKeyRotator",
           "DBApiSingleUserPasswordRotatorConstants",
           "DBApiSingleUserPasswordRotator",
           "DBPWDInputUnsafe",
           "DBApiMasterUserPasswordRotatorConstants",
           "DBApiMasterUserPasswordRotator"]
