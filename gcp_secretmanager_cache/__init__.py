# -*- coding: utf-8 -*-
"""gcp_secretmanager_cache

Some utilities to cache GCP secrets with a bit of intelligence and manage when they rotate and
trades off reliability, usability, predictability and performance vs accuracy and timeliness

"""

from __future__ import absolute_import

from gcp_secretmanager_cache.cache_secret import NoActiveSecretVersion, GCPCachedSecret
from gcp_secretmanager_cache.decorators import InjectKeywordedSecretString, InjectSecretString
from ._version import __version__

__all__ = ["NoActiveSecretVersion", "GCPCachedSecret", "InjectSecretString",
           "InjectKeywordedSecretString"]
