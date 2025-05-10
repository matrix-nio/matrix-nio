nio
===

[![Build Status](https://img.shields.io/github/actions/workflow/status/matrix-nio/matrix-nio/tests.yml?branch=main&style=flat-square)](https://github.com/matrix-nio/matrix-nio/actions)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/matrix-nio?style=flat-square)](https://pypi.org/project/matrix-nio/)
[![codecov](https://img.shields.io/codecov/c/github/matrix-nio/matrix-nio/master.svg?style=flat-square)](https://codecov.io/gh/matrix-nio/matrix-nio)
[![license](https://img.shields.io/badge/license-ISC-blue.svg?style=flat-square)](https://github.com/matrix-nio/matrix-nio/blob/master/LICENSE.md)
[![Documentation Status](https://readthedocs.org/projects/matrix-nio/badge/?version=latest&style=flat-square)](https://matrix-nio.readthedocs.io/en/latest/?badge=latest)
[![#nio](https://img.shields.io/badge/matrix-%23nio:matrix.org-blue.svg?style=flat-square)](https://matrix.to/#/!JiiOHXrIUCtcOJsZCa:matrix.org?via=matrix.org&via=maunium.net&via=t2l.io)

## Project Overview

**nio** is a multilayered [Matrix](https://matrix.org/) client library. The
underlying base layer doesn't do any network IO on its own, but on top of that
is a full-fledged batteries-included asyncio layer using
[aiohttp](https://github.com/aio-libs/aiohttp/). File IO is only done if you
enable end-to-end encryption (E2EE).

## Features
nio provides many features for working with Matrix, including but not limited to:
- ✅ transparent end-to-end encryption (EE2E)
- ✅ encrypted file uploads & downloads
- ✅ space parents/children
- ✅ manual and emoji verification
- ✅ custom [authentication types](https://matrix.org/docs/spec/client_server/r0.6.0#id183)
- ✅ threading support
- ✅ well-integrated type system
- ✅ knocking, kick, ban and unban
- ✅ typing notifications
- ✅ message redaction
- ✅ token-based login
- ✅ user registration
- ✅ read receipts
- ✅ live syncing
- ✅ `m.reaction`s
- ✅ `m.tag`s
- ❌ cross-signing support
- ❌ server-side key backups (room key backup, "Secure Backup")
- ❌ user deactivation ([#112](https://github.com/matrix-nio/matrix-nio/issues/112))
- ❌ in-room emoji verification

---

## Prerequisites
This project is built using Python. Make sure you have the following installed before proceeding:
- Python 3.x (refer to [PyPI](https://pypi.org/project/matrix-nio/) for compatible versions)
- [libolm](https://gitlab.matrix.org/matrix-org/olm) C library (version 3.x and for End-to-Edn Encryption)

### Supported Platforms:
- Debian/Ubuntu: Install `libolm-dev` using `apt-get`
- Fedora: Install `libolm-devel` using `dnf`
- macOS: Install `libolm` using [brew](https://brew.sh/)

---

## Installation Steps
### Option 1: Without End-to-End Encryption
Run the following command to install the base version of nio:
```bash
pip install matrix-nio
```

### Option 2: With End-to-End Encryption
To enable end-to-end encryption, install python-olm after ensuring `libolm` is installed:
```bash
pip install matrix-nio[e2e]
```

### Advanced Installation Options
Docker images with E2EE enabled versions of nio are provided in the `docker/` directory.

---

## Documentation
Comprehensive documentation for nio can be found at [Read the Docs](https://matrix-nio.readthedocs.io/en/latest/#api-documentation).

### Examples
For examples of how to use nio, and how others are using it, visit the [Examples Section](https://matrix-nio.readthedocs.io/en/latest/examples.html).

---

## Help and Support
For FAQs, common errors, and troubleshooting, visit [https://matrix-nio.readthedocs.io](https://matrix-nio.readthedocs.io/en/latest/#help-and-support).

Join discussions or ask for support on GitHub Issues and Pull Requests.
