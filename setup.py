# -*- coding: utf-8 -*-
"""bqtools-json a module for managing interaction between json data and big query.

This module provides utility functions for big query and specificially treaing big query as json
document database.
Schemas can be defined in json and provides means to create such structures by reading or passing
json structures.

"""

import setuptools
import re
from io import open

VERSIONFILE="gcp_secretmanager_cache/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name='gcp_secretmanager_cache',
    version=verstr,
    author="Mike Moore",
    author_email="z_z_zebra@yahoo.com",
    description="A utility to cache google cloud platform secrets and allow concurrent access that also always provides the latest enabled version of a secret",
    long_description_content_type="text/markdown",
    long_description=long_description,
    url="https://github.com/Mikemoore63/gcp-secretmanager-cache",
    packages=setuptools.find_packages(),
    test_suite='nose.collector',
    tests_require=['nose',
                   'psycopg2-binary~=2.0',
                   'PyMySQL',
                   'python-tds'],
    include_package_data=True,
    license="MIT",
    scripts=[],
    install_requires=[
        "google-cloud-secret-manager~=2.0",
        "google-api-python-client>1.0,<3.0",
        "google-cloud-storage>1.0,<4.0",
        "grpcio~=1.0",
        "python-dateutil~=2.0",
        "pytz>=2022.0"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],

)
