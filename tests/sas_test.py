from datetime import timedelta

import pytest

from helpers import faker
from nio.crypto import (
    OlmDevice,
    Sas,
    SasState,
    VerificationRequest,
    VerificationRequestState
)
from nio.events import (KeyVerificationAccept, KeyVerificationCancel,
                        KeyVerificationKey, KeyVerificationMac,
                        KeyVerificationStart, RoomKeyVerificationStart,
                        RoomKeyVerificationRequest, RoomKeyVerificationReady,
                        RoomKeyVerificationAccept, RoomKeyVerificationKey,
                        RoomKeyVerificationMac)
from nio.exceptions import LocalProtocolError
from nio.responses import RoomSendResponse

alice_id = "@alice:example.org"
alice_device_id = "JLAFKJWSCS"
alice_keys = faker.olm_key_pair(alice_device_id)

bob_id = "@bob:example.org"
bob_device_id = "JLAFKJWSRS"
bob_keys = faker.olm_key_pair(bob_device_id)

ROOM_ID = "!test:localhost"

alice_device = OlmDevice(
    alice_id,
    alice_device_id,
    alice_keys,
    ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"]
)

bob_device = OlmDevice(
    bob_id,
    bob_device_id,
    bob_keys,
    ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"]
)

@pytest.fixture
def alice_verification(alice_xsign, cross_signing_identity):
    _, _, _, alice_xsign = alice_xsign

    cross_signing_identity.user_id = bob_id

    return VerificationRequest(
        alice_id,
        alice_device_id,
        alice_keys[f"ed25519:{alice_device_id}"],
        alice_xsign,
        cross_signing_identity,
        room_id=ROOM_ID,
    )


class TestClass:
    def device_from_machine(self, machine):
        return OlmDevice(
            machine.user_id,
            machine.device_id,
            {
                f"{key_type}:{machine.device_id}": key for key_type,
                key in machine.account.identity_keys.items()
            },
            ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"]
        )

    @property
    def alice_sas(self):
        return Sas(
            alice_id,
            alice_device_id,
            alice_keys[f"ed25519:{alice_device_id}"],
            bob_device.user_id,
            bob_device
        )

    def wrap_room_message(self, sending_sas, message, event_class):
        message = {
            "sender": sending_sas.own_user,
            "room_id": ROOM_ID,
            "event_id": "test_id",
            "origin_server_ts": 10,
            "type": message.type,
            "content": message.as_dict(),
        }
        return event_class.from_dict(message)

    def test_sas_creation(self):
        alice = self.alice_sas

        with pytest.raises(LocalProtocolError):
            alice.accept_verification()

    def test_sas_start(self):
        alice = self.alice_sas
        assert alice.state == SasState.created

        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }

        start_event = KeyVerificationStart.from_dict(start)
        assert isinstance(start_event, KeyVerificationStart)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        with pytest.raises(LocalProtocolError):
            bob.start_verification()

        assert bob.state == SasState.started

    def test_sas_accept(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        assert isinstance(accept_event, KeyVerificationAccept)
        alice.receive_accept_event(accept_event)
        assert alice.state == SasState.accepted

    def test_sas_share_keys(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        alice.receive_accept_event(accept_event)

        alice_key = {
            "sender": alice_id,
            "content": alice.share_key().content
        }

        key_event = KeyVerificationKey.from_dict(alice_key)
        assert isinstance(key_event, KeyVerificationKey)
        bob.receive_key_event(key_event)
        assert bob.state == SasState.key_received

        bob_key = {
            "sender": bob_id,
            "content": bob.share_key().content
        }

        key_event = KeyVerificationKey.from_dict(bob_key)
        assert isinstance(key_event, KeyVerificationKey)
        alice.receive_key_event(key_event)
        assert alice.state == SasState.key_received
        assert alice.get_emoji() == bob.get_emoji()

    def test_sas_decimals(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        alice.receive_accept_event(accept_event)

        alice.set_their_pubkey(bob.pubkey)
        bob.set_their_pubkey(alice.pubkey)

        assert alice.get_decimals() == bob.get_decimals()

    def test_sas_invalid_commitment(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        alice.receive_accept_event(accept_event)

        alice_key = {
            "sender": alice_id,
            "content": alice.share_key().content
        }

        key_event = KeyVerificationKey.from_dict(alice_key)
        assert isinstance(key_event, KeyVerificationKey)
        bob.receive_key_event(key_event)
        assert bob.state == SasState.key_received

        bob_key = {
            "sender": bob_id,
            "content": bob.share_key().content
        }

        bob_key["content"]["key"] = alice.pubkey
        key_event = KeyVerificationKey.from_dict(bob_key)
        assert isinstance(key_event, KeyVerificationKey)
        alice.receive_key_event(key_event)
        assert alice.state == SasState.canceled

    def test_sas_mac(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        with pytest.raises(LocalProtocolError):
            alice.accept_sas()

        alice.set_their_pubkey(bob.pubkey)
        bob.set_their_pubkey(alice.pubkey)

        alice.state = SasState.key_received
        bob.state = SasState.key_received
        alice.chosen_mac_method = Sas._mac_normal
        bob.chosen_mac_method = Sas._mac_normal

        with pytest.raises(LocalProtocolError):
            alice.get_mac()

        alice.accept_sas()
        alice_mac = {
            "sender": alice_id,
            "content": alice.get_mac().content
        }

        mac_event = KeyVerificationMac.from_dict(alice_mac)
        assert isinstance(mac_event, KeyVerificationMac)
        assert not bob.verified

        bob.receive_mac_event(mac_event)
        assert bob.state == SasState.mac_received
        assert not bob.verified

        bob.accept_sas()
        assert bob.verified

    def test_sas_old_mac_method(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)
        start_event.message_authentication_codes.remove(Sas._mac_normal)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        with pytest.raises(LocalProtocolError):
            alice.accept_sas()

        alice.set_their_pubkey(bob.pubkey)
        bob.set_their_pubkey(alice.pubkey)

        alice.state = SasState.key_received
        bob.state = SasState.key_received
        alice.chosen_mac_method = Sas._mac_normal
        bob.chosen_mac_method = Sas._mac_normal

        with pytest.raises(LocalProtocolError):
            alice.get_mac()

        alice.accept_sas()
        alice_mac = {
            "sender": alice_id,
            "content": alice.get_mac().content
        }

        mac_event = KeyVerificationMac.from_dict(alice_mac)
        assert isinstance(mac_event, KeyVerificationMac)
        assert not bob.verified

        bob.receive_mac_event(mac_event)
        assert bob.state == SasState.mac_received
        assert not bob.verified

        bob.accept_sas()
        assert bob.verified

    def test_sas_cancellation(self):
        alice = self.alice_sas
        assert not alice.canceled

        with pytest.raises(LocalProtocolError):
            alice.get_cancellation()

        alice.cancel()
        assert alice.canceled

        with pytest.raises(LocalProtocolError):
            alice.start_verification()

        cancellation = alice.get_cancellation().content
        assert cancellation == {
            "transaction_id": alice.verification_flow_id,
            "code": "m.user",
            "reason": "Canceled by user"
        }

    def test_sas_invalid_start(self):
        alice = self.alice_sas

        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)
        start_event.method = "m.sas.v0"

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        assert bob.canceled

    def test_sas_reject(self):
        alice = self.alice_sas

        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        with pytest.raises(LocalProtocolError):
            alice.reject_sas()

        alice.set_their_pubkey(bob.pubkey)
        bob.set_their_pubkey(alice.pubkey)
        alice.state = SasState.key_received
        bob.state = SasState.key_received

        alice.reject_sas()

        assert alice.canceled

    def test_sas_timeout(self):
        alice = self.alice_sas

        assert not alice.timed_out

        minute = timedelta(minutes=1)
        alice.creation_time -= minute

        assert not alice.timed_out
        alice.creation_time -= (minute * 4)
        assert alice.timed_out
        assert alice.canceled

    def test_sas_event_timeout(self):
        alice = self.alice_sas
        minute = timedelta(minutes=1)

        assert not alice.timed_out
        alice._last_event_time -= minute
        assert alice.timed_out
        assert alice.canceled

    def test_sas_local_errors(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        alice.set_their_pubkey(bob.pubkey)
        alice.state = SasState.canceled
        bob.state = SasState.canceled

        with pytest.raises(LocalProtocolError):
            bob.accept_verification()

        with pytest.raises(LocalProtocolError):
            alice.share_key()

        alice.sas_accepted = True

        with pytest.raises(LocalProtocolError):
            alice.get_mac()

    def test_sas_not_ok_events(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )
        accept = {
            "sender": bob_id,
            "content": bob.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        accept_event.sender = faker.mx_id()
        alice.receive_accept_event(accept_event)
        assert alice.canceled

        alice.state = SasState.created
        accept_event.sender = bob_id
        accept_event.transaction_id = "fake_id"
        alice.receive_accept_event(accept_event)
        assert alice.canceled

        accept_event.transaction_id = alice.verification_flow_id
        alice.receive_accept_event(accept_event)
        assert alice.canceled

        alice.state = SasState.created
        accept_event.hash = "fake_hash"
        alice.receive_accept_event(accept_event)
        assert alice.canceled

        alice.state = SasState.created
        accept_event.hash = Sas._hash_v1
        alice.receive_accept_event(accept_event)
        alice_key = {
            "sender": alice_id,
            "content": alice.share_key().content
        }
        alice_key_event = KeyVerificationKey.from_dict(alice_key)

        alice_key_event.sender = faker.mx_id()
        bob.receive_key_event(alice_key_event)
        assert bob.canceled

        bob.set_their_pubkey(alice.pubkey)
        bob.state = SasState.key_received
        bob.chosen_mac_method = Sas._mac_normal

        alice.chosen_mac_method = Sas._mac_normal
        alice.set_their_pubkey(bob.pubkey)
        alice.state = SasState.key_received

        bob.accept_sas()
        bob_mac = {
            "sender": bob_id,
            "content": bob.get_mac().content
        }

        mac_event = KeyVerificationMac.from_dict(bob_mac)

        mac_event.sender = faker.mx_id()
        alice.receive_mac_event(mac_event)
        assert alice.canceled

    def test_sas_mac_before_key(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )
        bob.set_their_pubkey(alice.pubkey)
        bob.state = SasState.key_received

        bob.chosen_mac_method = Sas._mac_normal
        bob.accept_sas()
        bob_mac = {
            "sender": bob_id,
            "content": bob.get_mac().content
        }

        mac_event = KeyVerificationMac.from_dict(bob_mac)

        alice.receive_mac_event(mac_event)

        assert alice.canceled

    def test_sas_invalid_mac(self):
        alice = self.alice_sas
        start = {
            "sender": alice_id,
            "content": alice.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            start_event
        )

        with pytest.raises(LocalProtocolError):
            alice.accept_sas()

        alice.set_their_pubkey(bob.pubkey)
        bob.set_their_pubkey(alice.pubkey)

        alice.state = SasState.key_received
        bob.state = SasState.key_received
        alice.chosen_mac_method = Sas._mac_normal
        bob.chosen_mac_method = Sas._mac_normal

        alice.accept_sas()
        alice_mac = {
            "sender": alice_id,
            "content": alice.get_mac().content
        }

        mac_event = KeyVerificationMac.from_dict(alice_mac)
        mac_event.keys = "FAKEKEYS"

        bob.receive_mac_event(mac_event)
        assert bob.canceled
        assert not bob.verified

        bob.state = SasState.key_received
        assert not bob.canceled

        mac_event = KeyVerificationMac.from_dict(alice_mac)
        mac_event.mac["ed25519:{}".format(alice_device_id)] = "FAKEKEYS"

        bob.receive_mac_event(mac_event)
        assert bob.canceled
        assert not bob.verified

    def test_client_creation(self, olm_machine):
        bob_sas = Sas(
            bob_id,
            bob_device_id,
            olm_machine.account.identity_keys["ed25519"],
            bob_device.user_id,
            bob_device
        )

        start = {
            "sender": bob_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        assert olm_machine.device_store[bob_id][bob_device_id]
        olm_machine.handle_key_verification(start_event)

        alice_sas = olm_machine.key_verifications[start_event.transaction_id]

        assert alice_sas

    def test_client_gc(self, olm_machine):
        bob_sas = Sas(
            bob_id,
            bob_device_id,
            olm_machine.account.identity_keys["ed25519"],
            bob_device.user_id,
            bob_device
        )

        start = {
            "sender": bob_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)
        olm_machine.handle_key_verification(start_event)
        alice_sas = olm_machine.key_verifications[start_event.transaction_id]
        alice_sas.cancel()
        olm_machine.clear_verifications()
        alice_sas = olm_machine.key_verifications[start_event.transaction_id]
        assert alice_sas
        alice_sas.creation_time -= timedelta(minutes=25)
        olm_machine.clear_verifications()
        with pytest.raises(KeyError):
            alice_sas = (
                olm_machine.key_verifications[start_event.transaction_id]
            )

    def test_client_full_sas(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]
        bob_sas = Sas(
            bob_id,
            bob_device_id,
            bob_device.ed25519,
            alice_device.user_id,
            alice_device,
        )

        start = {
            "sender": bob_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        assert olm_machine.device_store[bob_id][bob_device_id]
        olm_machine.handle_key_verification(start_event)

        alice_sas = olm_machine.key_verifications[start_event.transaction_id]

        accept = {
            "sender": olm_machine.user_id,
            "content": alice_sas.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)

        bob_sas.receive_accept_event(accept_event)

        bob_key = {
            "sender": bob_id,
            "content": bob_sas.share_key().content
        }
        bob_key_event = KeyVerificationKey.from_dict(bob_key)

        assert bob_sas.chosen_key_agreement == Sas._key_agreement_v2
        assert alice_sas.chosen_key_agreement == Sas._key_agreement_v2

        olm_machine.handle_key_verification(bob_key_event)

        alice_key = {
            "sender": alice_id,
            "content": alice_sas.share_key().content
        }
        alice_key_event = KeyVerificationKey.from_dict(alice_key)
        bob_sas.receive_key_event(alice_key_event)

        assert alice_sas.other_key_set
        assert bob_sas.other_key_set

        bob_sas.accept_sas()

        bob_mac = {
            "sender": bob_id,
            "content": bob_sas.get_mac().content
        }

        bob_mac_event = KeyVerificationMac.from_dict(bob_mac)

        olm_machine.handle_key_verification(bob_mac_event)
        assert alice_sas.state == SasState.mac_received
        assert not alice_sas.verified

        alice_sas.accept_sas()
        assert alice_sas.verified
        bob_mac_event.keys = "fake_keys"
        olm_machine.handle_key_verification(bob_mac_event)
        assert alice_sas.verified

    def test_client_invalid_key(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_sas = Sas(
            bob_id,
            bob_device_id,
            faker.olm_key_pair("FAKEDEVICE")["ed25519:FAKEDEVICE"],
            alice_device.user_id,
            alice_device,
        )

        start = {
            "sender": bob_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)

        assert olm_machine.device_store[bob_id][bob_device_id]
        olm_machine.handle_key_verification(start_event)

        alice_sas = olm_machine.key_verifications[start_event.transaction_id]

        accept = {
            "sender": olm_machine.user_id,
            "content": alice_sas.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)

        bob_sas.receive_accept_event(accept_event)

        bob_key = {
            "sender": bob_id,
            "content": bob_sas.share_key().content
        }
        bob_key_event = KeyVerificationKey.from_dict(bob_key)

        olm_machine.handle_key_verification(bob_key_event)

        alice_key = {
            "sender": alice_id,
            "content": alice_sas.share_key().content
        }
        alice_key_event = KeyVerificationKey.from_dict(alice_key)
        bob_sas.receive_key_event(alice_key_event)

        assert alice_sas.other_key_set
        assert bob_sas.other_key_set

        bob_sas.accept_sas()

        bob_mac = {
            "sender": bob_id,
            "content": bob_sas.get_mac().content
        }

        bob_mac_event = KeyVerificationMac.from_dict(bob_mac)

        olm_machine.handle_key_verification(bob_mac_event)
        assert alice_sas.state == SasState.canceled
        assert not alice_sas.verified

        with pytest.raises(LocalProtocolError):
            alice_sas.accept_sas()

    def test_client_full_we_start(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]

        start = {
            "sender": alice_device.user_id,
            "content": olm_machine.create_sas(bob_device).content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob_sas = Sas.from_key_verification_start(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device,
            start_event
        )

        alice_sas = olm_machine.key_verifications[start_event.transaction_id]
        assert alice_sas

        accept = {
            "sender": bob_id,
            "content": bob_sas.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        olm_machine.handle_key_verification(accept_event)

        alice_key = {
            "sender": alice_id,
            "content": alice_sas.share_key().content
        }
        alice_key_event = KeyVerificationKey.from_dict(alice_key)
        bob_sas.receive_key_event(alice_key_event)

        bob_key = {
            "sender": bob_id,
            "content": bob_sas.share_key().content
        }
        bob_key_event = KeyVerificationKey.from_dict(bob_key)

        olm_machine.handle_key_verification(bob_key_event)

        assert alice_sas.other_key_set
        assert bob_sas.other_key_set

        bob_sas.accept_sas()

        bob_mac = {
            "sender": bob_id,
            "content": bob_sas.get_mac().content
        }

        bob_mac_event = KeyVerificationMac.from_dict(bob_mac)

        assert not olm_machine.is_device_verified(bob_device)
        alice_sas.accept_sas()
        olm_machine.handle_key_verification(bob_mac_event)
        assert alice_sas.state == SasState.mac_received
        assert alice_sas.verified
        assert olm_machine.is_device_verified(bob_device)

    def test_client_unknown_device(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)

        bob_device = faker.olm_device()

        bob_sas = Sas(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device.user_id,
            alice_device
        )

        start = {
            "sender": bob_device.user_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)
        olm_machine.handle_key_verification(start_event)

        assert start_event.transaction_id not in olm_machine.key_verifications
        assert bob_device.user_id in olm_machine.users_for_key_query

    def test_client_unsupported_method(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]

        bob_sas = Sas(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device.user_id,
            alice_device
        )

        start = {
            "sender": bob_device.user_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)
        start_event.method = "unsupported"
        assert not olm_machine.outgoing_to_device_messages

        olm_machine.handle_key_verification(start_event)

        assert start_event.transaction_id not in olm_machine.key_verifications
        assert olm_machine.outgoing_to_device_messages
        to_device = olm_machine.outgoing_to_device_messages[0]
        assert (
            start_event.transaction_id == to_device.content["transaction_id"]
        )

    def test_client_unknown_txid(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]

        bob_sas = Sas(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device.user_id,
            alice_device
        )

        start = {
            "sender": bob_device.user_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)
        olm_machine.handle_key_verification(start_event)

        bob_key = {
            "sender": bob_id,
            "content": bob_sas.share_key().content
        }
        bob_key_event = KeyVerificationKey.from_dict(bob_key)
        bob_key_event.transaction_id = "unknown"
        olm_machine.handle_key_verification(bob_key_event)
        alice_sas = olm_machine.key_verifications[start_event.transaction_id]
        assert alice_sas
        assert not alice_sas.other_key_set

        assert (
            bob_key_event.transaction_id not in olm_machine.key_verifications
        )

    def test_client_accept_cancel(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]

        start = {
            "sender": alice_device.user_id,
            "content": olm_machine.create_sas(bob_device).content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob_sas = Sas.from_key_verification_start(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device,
            start_event
        )

        alice_sas = olm_machine.key_verifications[start_event.transaction_id]
        assert alice_sas

        accept = {
            "sender": bob_id,
            "content": bob_sas.accept_verification().content
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        olm_machine.handle_key_verification(accept_event)
        assert not alice_sas.canceled
        olm_machine.handle_key_verification(accept_event)
        assert alice_sas.canceled

    def test_client_cancel_event(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]

        start = {
            "sender": alice_device.user_id,
            "content": olm_machine.create_sas(bob_device).content
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob_sas = Sas.from_key_verification_start(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device,
            start_event
        )

        alice_sas = olm_machine.key_verifications[start_event.transaction_id]
        assert alice_sas

        bob_sas.cancel()
        cancel = {
            "sender": bob_id,
            "content": bob_sas.get_cancellation().content
        }
        cancel_event = KeyVerificationCancel.from_dict(cancel)
        assert not alice_sas.canceled
        olm_machine.handle_key_verification(cancel_event)
        assert alice_sas.canceled
        assert alice_sas.verification_flow_id not in olm_machine.key_verifications

    def test_key_cancel(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]

        bob_sas = Sas(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device.user_id,
            alice_device
        )

        start = {
            "sender": bob_device.user_id,
            "content": bob_sas.start_verification().content
        }
        start_event = KeyVerificationStart.from_dict(start)
        olm_machine.handle_key_verification(start_event)

        bob_key = {
            "sender": bob_id,
            "content": bob_sas.share_key().content
        }
        assert not olm_machine.outgoing_to_device_messages
        bob_key_event = KeyVerificationKey.from_dict(bob_key)
        olm_machine.handle_key_verification(bob_key_event)
        alice_sas = olm_machine.key_verifications[start_event.transaction_id]

        assert alice_sas
        assert not alice_sas.canceled
        assert alice_sas.other_key_set

        olm_machine.handle_key_verification(bob_key_event)
        assert alice_sas.canceled
        assert olm_machine.outgoing_to_device_messages
        to_device = olm_machine.outgoing_to_device_messages[0]
        assert (
            start_event.transaction_id == to_device.content["transaction_id"]
        )

    def test_duplicate_verification(self, olm_machine):
        alice_device = self.device_from_machine(olm_machine)
        bob_device = olm_machine.device_store[bob_id][bob_device_id]

        bob_sas = Sas(
            bob_device.user_id,
            bob_device.id,
            bob_device.ed25519,
            alice_device.user_id,
            alice_device
        )
        start = {
            "sender": bob_device.user_id,
            "content": bob_sas.start_verification().content
        }

        start_event = KeyVerificationStart.from_dict(start)

        olm_machine.handle_key_verification(start_event)
        alice_sas = olm_machine.key_verifications[start_event.transaction_id]
        assert alice_sas
        olm_machine.handle_key_verification(start_event)

        assert alice_sas.canceled

        new_alice_sas = olm_machine.get_active_sas(bob_id, bob_device_id)
        assert new_alice_sas
        assert not new_alice_sas.canceled

    def test_client_sas_expiration(self, olm_machine):
        bob_device = olm_machine.device_store[bob_id][bob_device_id]
        olm_machine.create_sas(bob_device)
        sas = olm_machine.get_active_sas(bob_id, bob_device_id)
        assert sas

        olm_machine.clear_verifications()

        assert sas in olm_machine.key_verifications.values()
        minute = timedelta(minutes=1)
        sas.creation_time -= (minute * 5)

        olm_machine.clear_verifications()
        assert sas.canceled
        assert sas not in olm_machine.key_verifications.values()

    def test_sas_room_creation(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys[f"ed25519:{alice_device_id}"],
            bob_device.user_id,
            bob_device,
            room_id=ROOM_ID,
        )

        assert alice.room_id

        with pytest.raises(LocalProtocolError):
            alice.accept_verification()

    def test_verification_creation(self, alice_verification):
        alice = alice_verification

        with pytest.raises(ValueError):
            alice.get_ready_message()

    def test_request_full_flow(self, alice_verification):
        alice = alice_verification

        event = self.wrap_room_message(
            alice,
            alice.get_request_message(),
            RoomKeyVerificationRequest
        )
        response = RoomSendResponse("test_id", ROOM_ID)
        alice.receive_room_send_response(response)

        assert alice.verification_flow_id == response.event_id

        bob = VerificationRequest.from_request_event(
            alice.other_user_identity.user_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice.other_user_identity,
            alice.own_user_identity,
            event,
        )

        assert bob.state == VerificationRequestState.requested

        with pytest.raises(ValueError):
            bob.get_request_message()

        event = self.wrap_room_message(
            bob,
            bob.get_ready_message(),
            RoomKeyVerificationReady
        )

        alice.receive_ready_event(event)

        assert alice.state == VerificationRequestState.ready

        alice_sas = alice.into_sas_verification(bob_device)
        assert alice_sas.state == SasState.created

    def test_room_sas_start(self, alice_verification):
        alice = alice_verification
        assert alice.state == VerificationRequestState.created

        event = self.wrap_room_message(
            alice,
            alice.get_request_message(),
            RoomKeyVerificationRequest
        )

        bob = VerificationRequest.from_request_event(
            alice.other_user_identity.user_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice.other_user_identity,
            alice.own_user_identity,
            event,
        )

        bob_sas = bob.into_sas_verification(alice_device)
        assert bob_sas.state == SasState.created

    def test_sas_from_request_full(self, alice_verification):
        alice = alice_verification
        assert alice.state == VerificationRequestState.created

        event = self.wrap_room_message(
            alice,
            alice.get_request_message(),
            RoomKeyVerificationRequest
        )
        response = RoomSendResponse("test_id", ROOM_ID)
        alice.receive_room_send_response(response)

        bob = VerificationRequest.from_request_event(
            alice.other_user_identity.user_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice.other_user_identity,
            alice.own_user_identity,
            event,
        )

        event = self.wrap_room_message(
            bob,
            bob.get_ready_message(),
            RoomKeyVerificationReady,
        )
        alice.receive_ready_event(event)

        assert alice.state == VerificationRequestState.ready
        assert bob.state == VerificationRequestState.requested

        alice_sas = alice.into_sas_verification(bob_device)

        assert alice_sas.state == SasState.created

        event = self.wrap_room_message(
            alice_sas,
            alice_sas.start_verification(),
            RoomKeyVerificationStart,
        )

        bob_sas = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys[f"ed25519:{bob_device_id}"],
            alice_device,
            event
        )

        assert bob_sas.state == SasState.started

        assert alice_sas.room_id
        assert bob_sas.room_id

        event = self.wrap_room_message(bob_sas, bob_sas.accept_verification(), RoomKeyVerificationAccept)
        alice_sas.receive_accept_event(event)

        assert alice_sas.state == SasState.accepted

        event = self.wrap_room_message(alice_sas, alice_sas.share_key(), RoomKeyVerificationKey)
        bob_sas.receive_key_event(event)

        assert bob_sas.state == SasState.key_received

        event = self.wrap_room_message(bob_sas, bob_sas.share_key(), RoomKeyVerificationKey)
        alice_sas.receive_key_event(event)

        assert alice_sas.state == SasState.key_received

        alice_sas.accept_sas()
        bob_sas.accept_sas()

        event = self.wrap_room_message(bob_sas, bob_sas.get_mac(), RoomKeyVerificationMac)
        alice_sas.receive_mac_event(event)
        event = self.wrap_room_message(alice_sas, alice_sas.get_mac(), RoomKeyVerificationMac)
        bob_sas.receive_mac_event(event)

        assert alice_sas.state == SasState.mac_received
        assert alice_sas.verified
        assert bob_sas.state == SasState.mac_received
        assert bob_sas.verified

    def test_client_full_room_sas(self, olm_machine, alice_verification):
        room_id = ROOM_ID,
        alice = olm_machine

        alice_device = self.device_from_machine(alice)
        alice.cross_signing_store[bob_id] = alice_verification.other_user_identity
        alice.cross_signing_store[alice_id] = alice_verification.own_user_identity
        bob_device = alice.device_store[bob_id][bob_device_id]

        bob_verification = VerificationRequest(
            alice_verification.other_user_identity.user_id,
            bob_device_id,
            bob_device.ed25519,
            alice_verification.other_user_identity,
            alice_verification.own_user_identity,
            room_id=room_id,
        )
        response = RoomSendResponse("test_id", ROOM_ID)
        bob_verification.receive_room_send_response(response)

        event = self.wrap_room_message(bob_verification, bob_verification.get_request_message(), RoomKeyVerificationRequest)
        alice.handle_key_verification(event)

        alice_verification = alice.verification_requests[bob_id]
        assert alice_verification
        assert alice_verification.state == VerificationRequestState.requested

        event = self.wrap_room_message(alice_verification, alice_verification.get_ready_message(), RoomKeyVerificationReady)
        bob_verification.receive_ready_event(event)
        assert bob_verification.state == VerificationRequestState.ready

        bob_sas = bob_verification.into_sas_verification(alice_device)

        event = self.wrap_room_message(bob_sas, bob_sas.start_verification(), RoomKeyVerificationStart)
        alice.handle_key_verification(event)

        alice_sas = alice.key_verifications[event.relates_to]
        assert alice_sas.state == SasState.started

        _, message = alice.outgoing_room_messages.popitem()
        print(message)
        event = self.wrap_room_message(alice_sas, message, RoomKeyVerificationAccept)

        bob_sas.receive_accept_event(event)

        assert bob_sas.state == SasState.accepted

        event = self.wrap_room_message(bob_sas, bob_sas.share_key(), RoomKeyVerificationKey)
        alice.handle_key_verification(event)

        _, message = alice.outgoing_room_messages.popitem()
        event = self.wrap_room_message(alice_sas, message, RoomKeyVerificationKey)
        bob_sas.receive_key_event(event)

        assert alice_sas.state == SasState.key_received
        assert bob_sas.state == SasState.key_received

        assert alice_sas.get_emoji() == bob_sas.get_emoji()

        alice_sas.accept_sas()
        bob_sas.accept_sas()

        event = self.wrap_room_message(bob_sas, bob_sas.get_mac(), RoomKeyVerificationMac)
        alice.handle_key_verification(event)
        event = self.wrap_room_message(alice_sas, alice_sas.get_mac(), RoomKeyVerificationMac)
        bob_sas.receive_mac_event(event)

        assert alice_sas.state == SasState.mac_received
        assert alice_sas.verified
        assert bob_sas.state == SasState.mac_received
        assert bob_sas.verified
