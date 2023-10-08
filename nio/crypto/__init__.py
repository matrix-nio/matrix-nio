"""nio encryption module.

Encryption is handled mostly transparently to the user.

The main thing users need to worry about is device verification.

While device verification is handled in the Client classes of nio the classes
that are used to introspect OlmDevices or device authentication sessions are
documented here.

"""

import sys

from .._compat import package_installed
from .attachments import decrypt_attachment, encrypt_attachment

from .async_attachments import (
    AsyncDataT,
    async_encrypt_attachment,
    async_generator_from_data,
)

if package_installed("olm"):
    from .sessions import (  # isort:skip
        InboundGroupSession,
        InboundSession,
        OlmAccount,
        OutboundGroupSession,
        OutboundSession,
        Session,
    )
    from .device import DeviceStore, OlmDevice, TrustState
    from .key_request import OutgoingKeyRequest
    from .log import logger
    from .memorystores import GroupSessionStore, SessionStore
    from .olm_machine import Olm
    from .sas import Sas, SasState

    ENCRYPTION_ENABLED = True

else:
    ENCRYPTION_ENABLED = False
    from .device import DeviceStore, OlmDevice, TrustState
    from .key_request import OutgoingKeyRequest
