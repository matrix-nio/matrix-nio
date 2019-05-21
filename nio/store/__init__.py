from .._compat import package_installed

if package_installed("olm"):
    from .log import logger
    from .file_trustdb import Key, KeyStore, Ed25519Key
    from .models import (
        LegacyAccounts,
        LegacyOlmSessions,
        LegacyDeviceKeys,
        LegacyMegolmInboundSessions,
        LegacyForwardedChains,
        LegacyEncryptedRooms,
        LegacyOutgoingKeyRequests,
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
        TrustState,
        Keys
    )
    from .database import (
        DefaultStore,
        MatrixStore,
        LegacyMatrixStore,
        SqliteStore,
        SqliteMemoryStore,
        use_database,
        use_database_atomic
    )
