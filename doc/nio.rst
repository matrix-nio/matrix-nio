nio API
=======

This document details the API of nio.

Api
---

.. autoclass:: nio.Api
    :members:
    :undoc-members:

Client
-----------------

.. autoclass:: nio.Client
    :members:

AsyncClient
-----------

.. autoclass:: nio.AsyncClient
    :members:
    :undoc-members:
    :show-inheritance:


HttpClient
-----------------

.. autoclass:: nio.HttpClient
    :members:
    :undoc-members:
    :show-inheritance:

Rooms
----------------

.. automodule:: nio.rooms
    :members:
    :undoc-members:

Events
-----------------

.. automodule:: nio.events
    :members:
    :undoc-members:
    :show-inheritance:

.. automodule:: nio.events.misc
    :members:
    :show-inheritance:

Room Events
^^^^^^^^^^^^^^^^^

.. automodule:: nio.events.room_events
    :members:
    :undoc-members:
    :show-inheritance:

Invite Room Events
^^^^^^^^^^^^^^^^^^^^^^

.. automodule:: nio.events.invite_events
    :members:
    :undoc-members:
    :show-inheritance:

Account Data
^^^^^^^^^^^^^^^^^^^^^^

.. automodule:: nio.events.account_data
    :members:
    :undoc-members:
    :show-inheritance:


Exceptions
---------------------

.. automodule:: nio.exceptions
    :members:
    :undoc-members:
    :show-inheritance:

Responses
--------------------

.. automodule:: nio.responses
    :members:
    :undoc-members:


Storage
-----------------------
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
