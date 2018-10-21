# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name="matrix-nio",
    version="0.1",
    url="https://github.com/poljar/matrix-nio",
    author='Damir Jelić',
    author_email="poljar@termina.org.uk",
    description=("A Python Matrix client library, designed according to sans"
                 "I/O principles."),
    license="ISC",
    packages=["nio"],
    install_requires=["future", "typing", "h11", "h2", "olm"],
    zip_safe=False
)
