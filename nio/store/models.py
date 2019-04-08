# -*- coding: utf-8 -*-
# Copyright 2018 Zil0
# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
from datetime import datetime
from builtins import bytes

from peewee import (
    Model,
    TextField,
    IntegerField,
    BlobField,
    BooleanField,
    ForeignKeyField,
    CompositeKey,
)


class ByteField(BlobField):
    def python_value(self, value):  # pragma: no cover
        if isinstance(value, bytes):
            return value

        return bytes(value, "utf-8")

    def db_value(self, value):  # pragma: no cover
        if isinstance(value, bytearray):
            return bytes(value)

        return value


# Please don't remove this.
# This is a workaround for this bug: https://bugs.python.org/issue27400
class DateField(TextField):
    def python_value(self, value):  # pragma: no cover
        format = "%Y-%m-%d %H:%M:%S.%f"
        try:
            return datetime.strptime(value, format)
        except TypeError:
            return datetime(*(time.strptime(value, format)[0:6]))

    def db_value(self, value):  # pragma: no cover
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")


class LegacyAccounts(Model):
    account = ByteField()
    device_id = TextField(unique=True)
    shared = BooleanField()
    user_id = TextField(primary_key=True)

    class Meta:
        table_name = "accounts"


class LegacyDeviceKeys(Model):
    curve_key = TextField()
    deleted = BooleanField()
    device = ForeignKeyField(
        column_name="device_id",
        field="device_id",
        model=LegacyAccounts,
        on_delete="CASCADE"
    )
    ed_key = TextField()
    user_device_id = TextField()
    user_id = TextField()

    class Meta:
        table_name = "device_keys"
        indexes = (
            (("device", "user_id", "user_device_id"), True),
        )
        primary_key = CompositeKey("device", "user_device_id", "user_id")


class LegacyMegolmInboundSessions(Model):
    curve_key = TextField()
    device = ForeignKeyField(
        column_name="device_id",
        field="device_id",
        model=LegacyAccounts,
        on_delete="CASCADE"
    )
    ed_key = TextField()
    room_id = TextField()
    session = ByteField()
    session_id = TextField(primary_key=True)

    class Meta:
        table_name = "megolm_inbound_sessions"


class LegacyForwardedChains(Model):
    curve_key = TextField()
    session = ForeignKeyField(
        LegacyMegolmInboundSessions,
        backref="forwarded_chains",
        on_delete="CASCADE"
    )

    class Meta:
        table_name = "forwardedchains"


class LegacyEncryptedRooms(Model):
    room_id = TextField()
    account = ForeignKeyField(
        LegacyAccounts,
        backref="encrypted_rooms",
        on_delete="CASCADE"
    )

    class Meta:
        table_name = "encrytpedrooms"


class LegacyOlmSessions(Model):
    creation_time = DateField()
    curve_key = TextField()
    device = ForeignKeyField(
        column_name="device_id",
        field="device_id",
        model=LegacyAccounts,
        on_delete="CASCADE"
    )
    session = ByteField()
    session_id = TextField(primary_key=True)

    class Meta:
        table_name = "olm_sessions"


class LegacyOutgoingKeyRequests(Model):
    request_id = TextField()
    session_id = TextField()
    room_id = TextField()
    algorithm = TextField()
    device = ForeignKeyField(
        LegacyAccounts,
        on_delete="CASCADE",
        field="device_id",
        backref="key_requests",
    )

    class Meta:
        table_name = "outgoingkeyrequests"


class StoreVersion(Model):
    version = IntegerField()


class Accounts(Model):
    account = ByteField()
    device_id = TextField()
    shared = BooleanField()
    user_id = TextField()


class OlmSessions(Model):
    creation_time = DateField()
    last_usage_date = DateField()
    sender_key = TextField()
    account = ForeignKeyField(
        model=Accounts,
        backref="olm_sessions",
        on_delete="CASCADE"
    )
    session = ByteField()
    session_id = TextField(primary_key=True)


class DeviceKeys(Model):
    sender_key = TextField()
    deleted = BooleanField()
    account = ForeignKeyField(
        model=Accounts,
        backref="device_keys",
        on_delete="CASCADE",
    )
    fp_key = TextField()
    device_id = TextField()
    user_id = TextField()


class MegolmInboundSessions(Model):
    sender_key = TextField()
    account = ForeignKeyField(
        model=Accounts,
        backref="inbound_group_sessions",
        on_delete="CASCADE",
    )
    fp_key = TextField()
    room_id = TextField()
    session = ByteField()
    session_id = TextField(primary_key=True)


class ForwardedChains(Model):
    sender_key = TextField()
    session = ForeignKeyField(
        model=MegolmInboundSessions,
        backref="forwarded_chains",
        on_delete="CASCADE"
    )


class EncryptedRooms(Model):
    room_id = TextField()
    account = ForeignKeyField(
        model=Accounts,
        on_delete="CASCADE",
        backref="encrypted_rooms"
    )


class OutgoingKeyRequests(Model):
    request_id = TextField()
    session_id = TextField()
    room_id = TextField()
    algorithm = TextField()
    account = ForeignKeyField(
        model=Accounts,
        on_delete="CASCADE",
        backref="out_key_requests",
    )


class SyncTokens(Model):
    token = TextField()
    account = ForeignKeyField(
        model=Accounts,
        primary_key=True,
        on_delete="CASCADE",
        backref="sync_token",
    )


class TrackedUsers(Model):
    user_id = TextField()
    account = ForeignKeyField(
        model=Accounts,
        on_delete="CASCADE",
        backref="tracked_users",
    )
