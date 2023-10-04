from __future__ import annotations

from functools import wraps
from typing import Any, Iterator, List, Optional

from atomicwrites import atomic_write

from ..crypto import OlmDevice
from ..exceptions import OlmTrustError
from . import logger


class Key:
    def __init__(self, user_id: str, device_id: str, key: str):
        self.user_id = user_id
        self.device_id = device_id
        self.key = key

    @classmethod
    def from_line(cls, line: str) -> Optional[Key]:
        fields = line.split(" ")

        if len(fields) < 4:
            return None

        user_id, device_id, key_type, key = fields[:4]

        if key_type == "matrix-ed25519":
            return Ed25519Key(user_id.strip(), device_id.strip(), key.strip())
        else:
            return None

    def to_line(self) -> str:
        key_type = ""

        if isinstance(self, Ed25519Key):
            key_type = "matrix-ed25519"
        else:  # pragma: no cover
            raise NotImplementedError(f"Invalid key type {type(self.key)}")

        line = f"{self.user_id} {self.device_id} {key_type} {str(self.key)}\n"
        return line

    @classmethod
    def from_olmdevice(cls, device: OlmDevice) -> Ed25519Key:
        user_id = device.user_id
        device_id = device.id
        return Ed25519Key(user_id, device_id, device.ed25519)


class Ed25519Key(Key):
    def __eq__(self, value: Any) -> bool:
        if not isinstance(value, Ed25519Key):
            return NotImplemented

        if (
            self.user_id == value.user_id
            and self.device_id == value.device_id
            and self.key == value.key
        ):
            return True

        return False


class KeyStore:
    def __init__(self, filename: str):
        self._entries: List[Key] = []
        self._filename: str = filename

        self._load(filename)

    def __iter__(self) -> Iterator[Key]:
        yield from self._entries

    def __repr__(self) -> str:
        return f"KeyStore object, file: {self._filename}"

    def _load(self, filename: str):
        try:
            with open(filename) as f:
                for line in f:
                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    entry = Key.from_line(line)

                    if not entry:
                        continue

                    self._entries.append(entry)
        except FileNotFoundError:
            pass

    def get_key(self, user_id: str, device_id: str) -> Optional[Key]:
        for entry in self._entries:
            if user_id == entry.user_id and device_id == entry.device_id:
                return entry

        return None

    def _save_store(f):
        @wraps(f)
        def decorated(self, *args, **kwargs):
            ret = f(self, *args, **kwargs)
            self._save()
            return ret

        return decorated

    def _save(self):
        with atomic_write(self._filename, overwrite=True) as f:
            for entry in self._entries:
                line = entry.to_line()
                f.write(line)

    @_save_store  # type: ignore
    def add_many(self, keys: List[Key]):
        for key in keys:
            self._add_without_save(key)

    def _add_without_save(self, key: Key) -> bool:
        existing_key = self.get_key(key.user_id, key.device_id)

        if existing_key:
            if (
                existing_key.user_id == key.user_id
                and existing_key.device_id == key.device_id
                and type(existing_key) is type(key)
            ):
                if existing_key.key != key.key:
                    message = (
                        f"Error: adding existing device to trust store with "
                        f"mismatching fingerprint {key.key} {existing_key.key}"
                    )
                    logger.error(message)
                    raise OlmTrustError(message)

        self._entries.append(key)
        return True

    @_save_store  # type: ignore
    def add(self, key: Key) -> bool:
        return self._add_without_save(key)

    @_save_store  # type: ignore
    def remove_many(self, keys: List[Key]):
        for key in keys:
            if key in self._entries:
                self._entries.remove(key)

    @_save_store  # type: ignore
    def remove(self, key: Key) -> bool:
        if key in self._entries:
            self._entries.remove(key)
            return True

        return False

    def check(self, key: Key) -> bool:
        return key in self._entries
