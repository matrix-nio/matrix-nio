from .._compat import package_installed
from .attachments import encrypt_attachment, decrypt_attachment

if package_installed("olm"):
    from .sessions import (
        OlmAccount,
        Session,
        OutboundSession,
        InboundSession,
        OutboundGroupSession,
        InboundGroupSession,
        OlmDevice,
        OutgoingKeyRequest
    )

    from .memorystores import (
        SessionStore,
        GroupSessionStore,
        DeviceStore
    )

    from .log import logger

    from .olm_machine import Olm

    from .sas import Sas, SasState

    ENCRYPTION_ENABLED = True

else:
    ENCRYPTION_ENABLED = False
