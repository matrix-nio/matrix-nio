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
