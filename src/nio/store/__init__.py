"""Nio storage module.

This module contains storage classes that are used to store encryption devices,
encryption keys and the trust state of devices.

The module contains three store implementations one using a Sqlite database and
plaintext files to store keys and the truststate of devices, one that uses a
pure Sqlite database and one that stores the Sqlite database in memory.

User provided store types can be implemented by overriding the methods
provided in the MatrixStore base class.

isort:skip_file
"""

from .._compat import package_installed

if package_installed("olm"):
    from .log import logger
    from .file_trustdb import Ed25519Key, Key, KeyStore
    from .models import (
        Accounts,
        DeviceKeys,
        DeviceKeys_v1,
        DeviceTrustField,
        DeviceTrustState,
        EncryptedRooms,
        ForwardedChains,
        Keys,
        MegolmInboundSessions,
        OlmSessions,
        OutgoingKeyRequests,
        StoreVersion,
        SyncTokens,
    )
    from .database import (
        DefaultStore,
        MatrixStore,
        SqliteMemoryStore,
        SqliteStore,
        use_database,
        use_database_atomic,
    )
