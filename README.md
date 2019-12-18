nio  
===

[![Build Status](https://img.shields.io/travis/poljar/matrix-nio.svg?style=flat-square)](https://travis-ci.org/poljar/matrix-nio)
[![codecov](https://img.shields.io/codecov/c/github/poljar/matrix-nio/master.svg?style=flat-square)](https://codecov.io/gh/poljar/matrix-nio)
[![license](https://img.shields.io/badge/license-ISC-blue.svg?style=flat-square)](https://github.com/poljar/matrix-nio/blob/master/LICENSE.md)
[![Documentation Status](https://readthedocs.org/projects/matrix-nio/badge/?version=latest&style=flat-square)](https://matrix-nio.readthedocs.io/en/latest/?badge=latest)
[![#nio](https://img.shields.io/badge/matrix-%23nio:matrix.org-blue.svg?style=flat-square)](https://matrix.to/#/!JiiOHXrIUCtcOJsZCa:matrix.org?via=matrix.org&via=maunium.net&via=t2l.io)



nio is a multilayered matrix client library. The underlying base layer doesn't
do any IO on its own. On top of the base layer, a no-IO HTTP client
implementation exists, as well as a full fledged batteries included asyncio
layer using [aiohttp](https://github.com/aio-libs/aiohttp/).

Documentation
=============

The full API documentation for nio can be found at
[https://matrix-nio.readthedocs.io](https://matrix-nio.readthedocs.io/en/latest/#api-documentation)

Installation
============
To install nio, simply use pip:
```bash
$ pip install matrix-nio

```

Note that this installs nio without end-to-end encryption support. For e2ee
support, python-olm is needed which requires the
[libolm](https://gitlab.matrix.org/matrix-org/olm) C library (version 3.x).

After libolm has been installed, the e2ee enabled version of nio can be
installed using pip:

```bash
$ pip install "matrix-nio[e2e]"

```

Usage
=====

Unless special requirements disallow the usage of asyncio, by far the easiest
way to use nio is using the asyncio layer.

Please do note that these examples require python 3.5+ for the `async`/`await`
syntax. nio on the other hand works with older python versions as well.


Sending a message
-----------------

```python
import asyncio
from nio import AsyncClient

async def main():
    client = AsyncClient("https://example.org", "@alice:example.org")
    
    await client.login("hunter1")
    await client.room_send(
        room_id="!test:example.org",
        message_type="m.room.message",
        content={
            "msgtype": "m.text",
            "body": "Hello World"
        }
    )
    await client.close()

asyncio.get_event_loop().run_until_complete(main())
```

Receiving messages
------------------

```python
import asyncio
from nio import (AsyncClient, RoomMessageText)

async def message_cb(room, event):
    print(
        "Message received for room {} | {}: {}".format(
            room.display_name, room.user_name(event.sender), event.body
        )
    )

async def main():
    client = AsyncClient("https://example.org", "@alice:example.org")
    client.add_event_callback(message_cb, RoomMessageText)

    await client.login("hunter1")
    await client.sync_forever(timeout=30000)

asyncio.get_event_loop().run_until_complete(main())
```


