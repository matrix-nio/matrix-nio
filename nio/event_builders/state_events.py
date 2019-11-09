# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
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


"""Matrix state events module.

This module contains classes that can be used to easily create
room state event dicts.

For example, to turn on encryption in a room with the ``HttpClient`` or
``AsyncClient``, the ``EnableEncryptionBuilder`` class can be used:

    >>> event_dict = EnableEncryptionBuilder().as_dict()
    >>> client.room_send(
    ...     room_id      = "!test:example.com",
    ...     message_type = event_dict["type"],
    ...     content      = event_dict["content"],
    ... )
"""


@attr.s
class EnableEncryptionBuilder(object):
    """A state event that can be sent to enable encryption in a room.

    Attributes:
        algorithm (str): The algorithm to use for encrypting messages.
            The default ``m.megolm.v1.aes-sha2`` should not be changed.

        rotation_ms (int): How long in milliseconds an encrypted session
            should be used before changing it.
            The default ``604800000`` (a week) is recommended.

        rotation_msgs (int): How many messages can be received in a room before
            changing the encrypted session.
            The default ``100`` is recommended.

    """

    algorithm     = attr.ib(type=str, default="m.megolm.v1.aes-sha2")
    rotation_ms   = attr.ib(type=int, default=604800000)
    rotation_msgs = attr.ib(type=int, default=100)

    def as_dict(self):
        """Format the event as a dictionary."""
        return {
            "type":      "m.room.encryption",
            "state_key": "",
            "content":   {
                "algorithm":            self.algorithm,
                "rotation_period_ms":   self.rotation_ms,
                "rotation_period_msgs": self.rotation_msgs,
            },
        }
