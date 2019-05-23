# -*- coding: utf-8 -*-

from setuptools import find_packages, setup

setup(
    name="matrix-nio",
    version="0.3",
    url="https://github.com/poljar/matrix-nio",
    author='Damir Jelić',
    author_email="poljar@termina.org.uk",
    description=("A Python Matrix client library, designed according to sans "
                 "I/O principles."),
    license="ISC",
    packages=find_packages(),
    install_requires=[
        "attrs",
        "future",
        "aiohttp;python_version>'3.5'",
        "typing;python_version<'3.5'",
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
            "atomicwrites",
        ]
    },
    zip_safe=False
)
