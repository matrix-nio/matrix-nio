# -*- coding: utf-8 -*-

from os import path
from io import open
from setuptools import find_packages, setup

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="matrix-nio",
    version="0.9.0",
    url="https://github.com/poljar/matrix-nio",
    author='Damir Jelić',
    author_email="poljar@termina.org.uk",
    description=("A Python Matrix client library, designed according to sans "
                 "I/O principles."),
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="ISC",
    packages=find_packages(),
    install_requires=[
        "attrs",
        "future",
        "aiohttp;python_version>'3.5'",
        "aiofiles;python_version>'3.5'",
        "typing;python_version<'3.5'",
        "dataclasses;python_version<'3.7'",
        "h11",
        "h2",
        "logbook",
        "jsonschema",
        "unpaddedbase64",
        "pycryptodome",
    ],
    extras_require={
        "e2e":  [
            "python-olm>=3.1.0",
            "peewee>=3.9.5",
            "cachetools",
            "atomicwrites",
        ]
    },
    zip_safe=False
)
