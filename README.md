nio
===

[![Build Status](https://img.shields.io/github/workflow/status/poljar/matrix-nio/Build%20Status?style=flat-square)](https://github.com/poljar/matrix-nio/actions)
[![codecov](https://img.shields.io/codecov/c/github/poljar/matrix-nio/master.svg?style=flat-square)](https://codecov.io/gh/poljar/matrix-nio)
[![license](https://img.shields.io/badge/license-ISC-blue.svg?style=flat-square)](https://github.com/poljar/matrix-nio/blob/master/LICENSE.md)
[![Documentation Status](https://readthedocs.org/projects/matrix-nio/badge/?version=latest&style=flat-square)](https://matrix-nio.readthedocs.io/en/latest/?badge=latest)
[![#nio](https://img.shields.io/badge/matrix-%23nio:matrix.org-blue.svg?style=flat-square)](https://matrix.to/#/!JiiOHXrIUCtcOJsZCa:matrix.org?via=matrix.org&via=maunium.net&via=t2l.io)

nio is a multilayered [Matrix](https://matrix.org/) client library. The
underlying base layer doesn't do any network IO on its own, but on top of that
is a full-fledged batteries-included asyncio layer using
[aiohttp](https://github.com/aio-libs/aiohttp/). File IO is only done if you
enable end-to-end encryption (E2EE).

Documentation
-------------

The full API documentation for nio can be found at
[https://matrix-nio.readthedocs.io](https://matrix-nio.readthedocs.io/en/latest/#api-documentation)

Features
--------

nio has most of the features you'd expect in a Matrix library, but it's still a work in progress.

- ✅ transparent end-to-end encryption (EE2E)
- ✅ encrypted file uploads & downloads
- ✅ space parents/children
- ✅ manual and emoji verification
- ✅ custom [authentication types](https://matrix.org/docs/spec/client_server/r0.6.0#id183)
- ✅ well-integrated type system
- ✅ knocking, kick, ban and unban
- ✅ typing notifications
- ✅ message redaction
- ✅ token based login
- ✅ user registration
- ✅ read receipts
- ✅ live syncing
- ✅ `m.reaction`s
- ✅ `m.tag`s
- ❌ cross-signing support
- ❌ server-side key backups (room key backup, "Secure Backup")
- ❌ user deactivation ([#112](https://github.com/poljar/matrix-nio/issues/112))
- ❌ threading support
- ❌ in-room emoji verification

Installation
------------

To install nio, simply use pip:

```bash
$ pip install matrix-nio

```

Note that this installs nio without end-to-end encryption support. For e2ee
support, python-olm is needed which requires the
[libolm](https://gitlab.matrix.org/matrix-org/olm) C library (version 3.x).
On Debian and Ubuntu one can use `apt-get` to install package `libolm-dev`.
On Fedora one can use `dnf` to install package `libolm-devel`.
On MacOS one can use [brew](https://brew.sh/) to install package `libolm`.
Make sure version 3 is installed.

After libolm has been installed, the e2ee enabled version of nio can be
installed using pip:

```bash
$ pip install "matrix-nio[e2e]"

```

Additionally, a docker image with the e2ee enabled version of nio is provided in
the `docker/` directory.

Examples
--------

For examples of how to use nio, and how others are using it,
[read the docs](https://matrix-nio.readthedocs.io/en/latest/examples.html)
