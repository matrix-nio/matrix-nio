"""Nio storage module.

This module contains storage classes that are used to store encryption devices,
encryption keys and the trust state of devices.

The module contains three store implementations one using a Sqlite database and
plaintext files to store keys and the truststate of devices, one that uses a
pure Sqlite database and one that stores the Sqlite database in memory.

User provided store types can be implemented by overriding the methods
provided in the MatrixStore base class.

"""

from .._compat import package_installed

if package_installed("olm"):
    from .log import logger
    from .file_trustdb import Key, KeyStore, Ed25519Key
    from .models import (
        DeviceKeys_v1,
        Accounts,
        OlmSessions,
        DeviceKeys,
        MegolmInboundSessions,
        ForwardedChains,
        EncryptedRooms,
        OutgoingKeyRequests,
        DeviceTrustState,
        DeviceTrustField,
        StoreVersion,
        Keys,
        SyncTokens
    )
    from .database import (
        DefaultStore,
        MatrixStore,
        SqliteStore,
        SqliteMemoryStore,
        use_database,
        use_database_atomic
    )
