API
===

This document details the API of nio.

Logging
-------

matrix-nio writes logs using python's standard `logging` module. In order to see these logs, you will need to configure
`logging`. In order to see all logs matrix-nio produces, you can build off of the following snippet::

    import logging

    logging.basicConfig(level=logging.DEBUG)

This snippet is very loud, and will produce a lot of output. If you want to see less output, you can set the logging
level to `INFO` or `WARNING`. For example::

    import logging

    logging.basicConfig(level=logging.INFO)

In production, it is recommended to use WARNING or higher, as INFO may still be too noisy.

You can also attach your own logs to this system::

    import logging

    logging.basicConfig(level=logging.DEBUG)

    logger = logging.getLogger("my-app")
    logger.info("Hello, world!")

For more information, seek the documentation for the `logging` module at https://docs.python.org/3/library/logging.html

Api
---

.. autoclass:: nio.Api
    :members:
    :undoc-members:

nio Clients
-----------

.. automodule:: nio.client

.. autoclass:: nio.ClientConfig
    :members:

Client
^^^^^^
.. autoclass:: nio.Client
    :members:

AsyncClient
^^^^^^^^^^^

.. autoclass:: nio.AsyncClient
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: nio.TransferMonitor
    :members:
    :undoc-members:
    :show-inheritance:

HttpClient
^^^^^^^^^^

.. autoclass:: nio.HttpClient
    :members:
    :undoc-members:
    :show-inheritance:

Rooms
-----

.. automodule:: nio.rooms
    :members:
    :undoc-members:
    :show-inheritance:

Events
------

.. automodule:: nio.events
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: nio.events.misc
    :members:
    :show-inheritance:

Room Events
^^^^^^^^^^^

.. automodule:: nio.events.room_events
    :members:
    :undoc-members:
    :show-inheritance:

Invite Room Events
^^^^^^^^^^^^^^^^^^

.. automodule:: nio.events.invite_events
    :members:
    :undoc-members:
    :show-inheritance:

Room Knocking Events
^^^^^^^^^^^^^^^^^^

.. automodule:: nio.events.knock_events
    :members:
    :undoc-members:
    :show-inheritance:

To-device Events
^^^^^^^^^^^^^^^^

.. automodule:: nio.events.to_device
    :members:
    :undoc-members:
    :show-inheritance:

Ephemeral Events
^^^^^^^^^^^^^^^^

.. automodule:: nio.events.ephemeral
    :members:
    :undoc-members:
    :show-inheritance:

Account Data
^^^^^^^^^^^^

.. automodule:: nio.events.account_data
    :members:
    :undoc-members:
    :show-inheritance:


Building events
---------------
.. automodule:: nio.event_builders
    :members:
    :show-inheritance:

.. autoclass:: nio.event_builders.EventBuilder
    :members:
    :show-inheritance:

Direct messages
^^^^^^^^^^^^^^^

.. automodule:: nio.event_builders.direct_messages
    :members:
    :show-inheritance:

State events
^^^^^^^^^^^^

.. automodule:: nio.event_builders.state_events
    :members:
    :show-inheritance:


Exceptions
----------

.. automodule:: nio.exceptions
    :members:
    :undoc-members:
    :show-inheritance:

Responses
---------

.. automodule:: nio.responses
    :members:
    :undoc-members:


Storage
-------
.. automodule:: nio.store
    :members:
    :undoc-members:

.. autoclass:: nio.store.MatrixStore
    :members:

.. autoclass:: nio.store.DefaultStore
    :show-inheritance:

.. autoclass:: nio.store.SqliteStore
    :show-inheritance:

.. autoclass:: nio.store.SqliteMemoryStore
    :show-inheritance:

Encryption
----------
.. automodule:: nio.crypto

.. autoclass:: nio.crypto.DeviceStore
    :members:

.. autoclass:: nio.crypto.OlmDevice
    :members:

.. autoclass:: nio.crypto.TrustState
    :members:

.. autoclass:: nio.crypto.Sas
    :members:
