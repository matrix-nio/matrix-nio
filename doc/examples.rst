Examples
========

If you've built something with matrix-nio and want to support the project, add a shield!

.. image:: https://img.shields.io/badge/built%20with-matrix--nio-brightgreen
    :target: https://github.com/poljar/matrix-nio
    :alt: Built with matrix-nio

.. code-block::

    [![Built with matrix-nio](https://img.shields.io/badge/built%20with-matrix--nio-brightgreen)](https://github.com/poljar/matrix-nio)

To start making a chat bot quickly, considering using `nio-template <https://github.com/anoadragon453/nio-template>`_.

.. Attention::
    For E2EE support, ``python-olm`` is needed, which requires the
    `libolm <https://gitlab.matrix.org/matrix-org/olm>`_ C library
    (version 3.x). After libolm has been installed, the e2ee enabled version of
    nio can be installed using pip:

    .. code-block::

        $ pip install "matrix-nio[e2e]"


.. include:: built-with-nio.rst


A basic client
--------------

A basic client requires a few things before you start:

- nio is installed
- a Matrix homeserver URL (probably "https://matrix.example.org")
- a username and password for an account on that homeserver
- a room ID for a room on that homeserver. In Riot, this is found in the Room's
  settings page under "Advanced"

By far the easiest way to use nio is using the asyncio layer, unless you have
special restrictions that disallow the use of asyncio.

All examples require Python 3.5+ for the ``async / await`` syntax.

.. literalinclude:: ../examples/basic_client.py
   :language: python
   :linenos:


Log in using a stored access_token
----------------------------------

Using access tokens requires that when you first log in you save a few values
to use later. In this example, we're going to write them to disk as a JSON
object, but you could also store them in a database, print them out and post
them up on the wall beside your desk, text them to your sister in law, or
anything else that allows you access to the values at a later date.

We've tried to keep this example small enough that it's just enough to work;
once you start writing your own programs with nio you may want to clean things
up a bit.

This example requires that the user running it has write permissions to the
folder they're in. If you copied this repo to your computer, you probably have
write permissions.

.. literalinclude:: ../examples/restore_login.py
    :language: python
    :linenos:


Manual encryption key verification
----------------------------------

Below is a program that works through manual encryption of other users when you
already know all of their device IDs. It's written in a manner that expects you
to read through the code and comments from top to bottom before trying to run
it.

You'll need two accounts, which we'll call @alice:example.org and
@bob:example.org. @alice will be your nio application and @bob will be your
second user account. Before the script runs, **make a new room** with the
@bob account, enable encryption and invite @alice. Note the room ID as you'll
need it for this script. You'll also need **all** of @bob's device IDs, which
you can get from within Riot under the profile settings > Advanced section.
They may be called "session IDs". These are the device IDs that your program
will trust, and getting them into nio is the manual part here. In another
example we'll document automatic emoji verification.

By design, this is a **minimal possible demo** of working encryption and
verification. It is not a working chatbot and you will have to adjust the design
so that you accept messages as they come in, sync forever, receive room invites,
or anything else you'd like your bot to do. It may look long at first but much
of the program is actually documentation explaining how it works. If you have
questions about the example, please don't hesitate to ask them on
`#nio:matrix.org <https://matrix.to/#/!JiiOHXrIUCtcOJsZCa:matrix.org?via=matrix.org&via=maunium.net&via=t2l.io>`_.

If you are stuck, it may be useful to read this primer from Matrix.org on
implementing end-to-end encryption:
https://matrix.org/docs/guides/end-to-end-encryption-implementation-guide

.. literalinclude:: ../examples/manual_encrypted_verify.py
    :language: python
    :linenos:


Interactive encryption key verification
---------------------------------------

We're working on writing this!

