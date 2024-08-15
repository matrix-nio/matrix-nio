import logging
from dataclasses import dataclass, field
from typing import Optional

from ..schemas import Schemas
from .misc import verify

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


logger = logging.getLogger(__name__)


@dataclass
class PresenceEvent:
    """Informs the client of a user's presence state change."""

    user_id: str = field()
    presence: str = field()
    last_active_ago: Optional[int] = None
    currently_active: Optional[bool] = None
    status_msg: Optional[str] = None

    @classmethod
    @verify(Schemas.presence)
    def from_dict(cls, parsed_dict):
        """Create an Presence event from a dictionary.

        Args:
            parsed_dict (dict): The dictionary representation of the event.

        """
        args = {
            "user_id": parsed_dict["sender"],
            "presence": parsed_dict["content"]["presence"],
        }

        if "last_active_ago" in parsed_dict["content"]:
            args["last_active_ago"] = parsed_dict["content"]["last_active_ago"]
        if "currently_active" in parsed_dict["content"]:
            args["currently_active"] = parsed_dict["content"]["currently_active"]
        if "status_msg" in parsed_dict["content"]:
            args["status_msg"] = parsed_dict["content"]["status_msg"]

        return cls(**args)
