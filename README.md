nio  
===

[![Build Status](https://img.shields.io/travis/poljar/matrix-nio.svg?style=flat-square)](https://travis-ci.org/poljar/matrix-nio)
[![codecov](https://img.shields.io/codecov/c/github/poljar/matrix-nio/master.svg?style=flat-square)](https://codecov.io/gh/poljar/matrix-nio)
[![license](https://img.shields.io/badge/license-ISC-blue.svg?style=flat-square)](https://github.com/poljar/matrix-nio/blob/master/LICENSE.md)
[![Documentation Status](https://readthedocs.org/projects/matrix-nio/badge/?version=latest&style=flat-square)](https://matrix-nio.readthedocs.io/en/latest/?badge=latest)
[![#nio](https://img.shields.io/badge/matrix-%23nio:matrix.org-blue.svg?style=flat-square)](https://matrix.to/#/!twcBhHVdZlQWuuxBhN:termina.org.uk?via=termina.org.uk&via=matrix.org)



A no-IO matrix client library. Mainly developed to be used with weechat, other
users are welcome.

Installation
============
To install nio, simply use pip:
```bash
$ pip install matrix-nio

```

Note that this installs nio without end-to-end encryption support. For e2ee
support python-olm is needed which requires a the
[libolm](https://gitlab.matrix.org/matrix-org/olm) C library.

After libolm has been installed the e2ee enabled version of  nio can be
installed using pip:

```bash
$ pip install matrix-nio[e2e]

```

Documentation
=============

Documentation is in progress and can be found [here](https://matrix-nio.readthedocs.io/en/latest/nio.html)
