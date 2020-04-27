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
