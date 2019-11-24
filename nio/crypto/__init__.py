"""nio encryption module.

Encryption is handled mostly transparently to the user.

The main thing users need to worry about is device verification.

While device verification is handled in the Client classes of nio the classes
that are used to introspect OlmDevices or device authentication sessions are
documented here.

"""

import sys

from .._compat import package_installed
from .attachments import encrypt_attachment, decrypt_attachment

if sys.version_info >= (3, 5):
    from .async_attachments import (AsyncDataT, async_encrypt_attachment,
                                    async_generator_from_data,)

if package_installed("olm"):
    from .sessions import (
        OlmAccount,
        Session,
        OutboundSession,
        InboundSession,
        OutboundGroupSession,
        InboundGroupSession,
        OlmDevice,
        OutgoingKeyRequest,
        TrustState
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
