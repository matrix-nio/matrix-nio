# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="matrix-nio",
    version="0.2",
    url="https://github.com/poljar/matrix-nio",
    author='Damir Jelić',
    author_email="poljar@termina.org.uk",
    description=("A Python Matrix client library, designed according to sans"
                 "I/O principles."),
    license="ISC",
    packages=find_packages(),
    install_requires=[
        "attrs",
        "future",
        "peewee<=3.9.3",
        "aiohttp;python_version>'3.5'",
        "typing;python_version<'3.5'",
        "h11",
        "h2",
        "logbook",
        "jsonschema",
        "atomicwrites",
        "unpaddedbase64",
        "pycryptodome",
        "python-olm>=3.1.0",
    ],
    zip_safe=False
)
