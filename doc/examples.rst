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
    nio can be installed using ``pip install "matrix-nio[e2e]"``.

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
write permissions. Now run the program `restore_login.py` twice.
First time around it will ask
you for credentials like homeserver and password. On the second run, the
program will log in for you automatically and it will send a "Hello World"
message to the room you specify.

.. literalinclude:: ../examples/restore_login.py
    :language: python
    :linenos:


Sending an image
----------------------------------
Now that you have sent a first "Hello World" text message, how about
going one step further and sending an image, like a photo from your last
vacation. Run the `send_image.py` program and provide a filename to
the photo. Voila, you have just sent your first image!

.. literalinclude:: ../examples/send_image.py
    :language: python
    :linenos:


Manual encryption key verification
----------------------------------

Below is a program that works through manual encryption of other users when you
already know all of their device IDs. It's a bit dense but provides a good
example in terms of being pythonic and using nio's design features purposefully.
It is not designed to be a template that you can immediately extend to run your
bot, it's designed to be an example of how to use nio.

The overall structure is this: we subclass nio's ``AsyncClient`` class and add
in our own handlers for a few things, namely:

- automatically restoring login details from disk instead of creating new sessions each time we restart the process
- callback for printing out any message we receive to stdout
- callback for automatically joining any room @alice is invited to
- a method for trusting devices using a user ID and (optionall) their list of trusted device IDs
- a sample "hello world" encrypted message method

In main, we make an instance of that subclass, attempt to login, then create an
`asyncio coroutine <https://docs.python.org/3/library/asyncio-task.html#coroutines>`_
to run later that will trust the devices and send the hello world message. We
then create
`asyncio Tasks <>`_
to run that coroutine as well as the ``sync_forever()`` coroutine that nio
provides, which does most of the handling of required work for communicating
with Matrix: it uploads keys, checks for new messages, executes callbacks when
events occur that trigger those callbacks, etc. Main executes the result of
those Tasks.

You'll need two accounts, which we'll call @alice:example.org and
@bob:example.org. @alice will be your nio application and @bob will be your
second user account. Before the script runs, **make a new room** with the
@bob account, enable encryption and invite @alice. Note the room ID as you'll
need it for this script. You'll also need **all** of @bob's device IDs, which
you can get from within Riot under the profile settings > Advanced section.
They may be called "session IDs". These are the device IDs that your program
will trust, and getting them into nio is the manual part here. In another
example we'll document automatic emoji verification.

It may look long at first but much of the program is actually documentation
explaining how it works. If you have questions about the example, please
don't hesitate to ask them on
`#nio:matrix.org <https://matrix.to/#/!JiiOHXrIUCtcOJsZCa:matrix.org?via=matrix.org&via=maunium.net&via=t2l.io>`_.

If you are stuck, it may be useful to read this primer from Matrix.org on
implementing end-to-end encryption:
https://matrix.org/docs/guides/end-to-end-encryption-implementation-guide

To delete the store, or clear the trusted devices, simply remove "nio_store" in
the working directory as well as "manual_encrypted_verify.json". Then the
example script will log in (with a new session ID) and generate new keys.

.. literalinclude:: ../examples/manual_encrypted_verify.py
    :language: python
    :linenos:


Interactive encryption key verification
---------------------------------------

One way to interactively verify a device is via emojis. On popular Matrix
clients you will find that devices are flagged as `trusted` or `untrusted`.
If a device is `untrusted` you can verify to make it `trusted`. Most
clients have a red symbol for `untrusted` and a green icon for `trusted`.
One can select an untrusted device and initiate a `verify by emoji`
action. How would that look like in code? How can you add that to your
application? Next we present a simple application that showcases
emoji verification. Note, the app only accepts emoji verification. So,
you have to start it on the other client (e.g. Element). Initiating an
emoji verification is similar in code, consider doing it as "homework"
if you feel up to it. But for now, let's have a look how emoji verification
can be accepted and processed.

.. literalinclude:: ../examples/verify_with_emoji.py
    :language: python
    :linenos:


Further reading and exploration
---------------------------------------

In an external repo, not maintained by us, is a simple Matix client
that includes sending, receiving and verification. It gives an example
of

- how to send text, images, audio, video, other text files
- listen to messages forever
- get just the newest unread messages
- get the last N messages
- perform emoji verification
- etc.

So, if you want more example code and want to explore further have a
look at this external repo called
`matrix-commander <https://github.com/8go/matrix-commander>`_.
And of course, you should check out all the other projects built
with `matrix-nio`. To do so, check out our
`built-with-marix-nio list <https://github.com/poljar/matrix-nio/blob/master/doc/built-with-nio.rst>`_.
