# -*- coding: utf-8 -*-

# Copyright © 2018-2019 Damir Jelić <poljar@termina.org.uk>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import attr
from typing import Any, Dict, Optional, Union

from ..schemas import Schemas

from .misc import BadEventType, verify
from .encrypted_events import RoomEncryptedEvent


@attr.s
class ToDeviceEvent(object):
    sender = attr.ib()

    @classmethod
    @verify(Schemas.to_device)
    def parse_event(
        cls,
        event_dict  # type: Dict[Any, Any]
    ):
        # type: (...) -> Optional[Union[ToDeviceEvent, BadEventType]]
        # A redacted event will have an empty content.
        if not event_dict["content"]:
            return None

        if event_dict["type"] == "m.room.encrypted":
            return RoomEncryptedEvent.parse_event(event_dict)

        return None
