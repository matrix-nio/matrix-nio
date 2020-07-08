# Copyright © 2020 The Matrix.org Foundation C.I.C.
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

from typing import Dict, Any, Union
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from . import EventBuilder


@dataclass
class RoomEvent(EventBuilder):
    """An event that can be sent as a message to a room.

    Attributes:
        room_id (str): The room that the event should be sent to.
        type (str): The type of the event.
        content (Dict[Any, Any]): The content of the event.
    """

    room_id: str = field()
    type: str = field()
    content: Dict[Any, Any] = field()
    transaction_id: Union[str, UUID] = field(default=uuid4())

    def as_dict(self):
        return self.content
