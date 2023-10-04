# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
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

from collections import defaultdict
from typing import DefaultDict, Dict, Iterator, List, Optional

from .sessions import InboundGroupSession, Session


class SessionStore:
    def __init__(self):
        self._entries: DefaultDict[str, List[Session]] = defaultdict(list)

    def add(self, sender_key: str, session: Session) -> bool:
        if session in self._entries[sender_key]:
            return False

        self._entries[sender_key].append(session)
        self._entries[sender_key].sort(key=lambda x: x.use_time, reverse=True)
        return True

    def __iter__(self) -> Iterator[Session]:
        for session_list in self._entries.values():
            yield from session_list

    def values(self):
        return self._entries.values()

    def items(self):
        return self._entries.items()

    def get(self, sender_key: str) -> Optional[Session]:
        if self._entries[sender_key]:
            return self._entries[sender_key][0]

        return None

    def __getitem__(self, sender_key: str) -> List[Session]:
        return self._entries[sender_key]


class GroupSessionStore:
    def __init__(self):
        self._entries = defaultdict(lambda: defaultdict(dict))

    def __iter__(self) -> Iterator[InboundGroupSession]:
        for room_sessions in self._entries.values():
            for sender_sessions in room_sessions.values():
                yield from sender_sessions.values()

    def add(self, session: InboundGroupSession) -> bool:
        room_id = session.room_id
        sender_key = session.sender_key
        if session in self._entries[room_id][sender_key].values():
            return False

        self._entries[room_id][sender_key][session.id] = session
        return True

    def get(
        self, room_id: str, sender_key: str, session_id: str
    ) -> Optional[InboundGroupSession]:
        if session_id in self._entries[room_id][sender_key]:
            return self._entries[room_id][sender_key][session_id]

        return None

    def __getitem__(
        self, room_id: str
    ) -> DefaultDict[str, Dict[str, InboundGroupSession]]:
        return self._entries[room_id]
