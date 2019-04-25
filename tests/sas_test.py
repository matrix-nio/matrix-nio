import pytest

from nio.crypto import Sas, SasState, OlmDevice
from nio.exceptions import LocalProtocolError
from nio.events import (
    KeyVerificationStart,
    KeyVerificationAccept,
    KeyVerificationKey,
    KeyVerificationMac
)
from helpers import faker

alice_id = faker.mx_id()
alice_device_id = faker.device_id()
alice_keys = faker.olm_key_pair()

bob_id = faker.mx_id()
bob_device_id = faker.device_id()
bob_keys = faker.olm_key_pair()

alice_device = OlmDevice(
    alice_id,
    alice_device_id,
    alice_keys["ed25519"],
    alice_keys["curve25519"]
)

bob_device = OlmDevice(
    bob_id,
    bob_device_id,
    bob_keys["ed25519"],
    bob_keys["curve25519"]
)


class TestClass(object):
    def test_sas_creation(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device
        )

        with pytest.raises(LocalProtocolError):
            alice.accept_verification()

    def test_sas_start(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device,
        )
        assert alice.state == SasState.created

        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }

        start_event = KeyVerificationStart.from_dict(start)
        assert isinstance(start_event, KeyVerificationStart)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys["ed25519"],
            alice_device,
            start_event
        )

        assert bob.state == SasState.started

    def test_sas_accept(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device,
        )
        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device,
            bob_keys["ed25519"],
            alice_device,
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification()
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        assert isinstance(accept_event, KeyVerificationAccept)
        alice.receive_accept_event(accept_event)
        assert alice.state == SasState.accepted

    def test_sas_share_keys(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device,
        )
        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys["ed25519"],
            alice_device,
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification()
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        alice.receive_accept_event(accept_event)

        alice_key = {
            "sender": alice_id,
            "content": alice.share_key()
        }

        key_event = KeyVerificationKey.from_dict(alice_key)
        assert isinstance(key_event, KeyVerificationKey)
        bob.receive_key_event(key_event)
        assert bob.state == SasState.key_received

        bob_key = {
            "sender": bob_id,
            "content": bob.share_key()
        }

        key_event = KeyVerificationKey.from_dict(bob_key)
        assert isinstance(key_event, KeyVerificationKey)
        alice.receive_key_event(key_event)
        assert alice.state == SasState.key_received
        assert alice.get_emoji() == bob.get_emoji()

    def test_sas_decimals(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device,
        )
        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys["ed25519"],
            alice_device,
            start_event
        )

        alice.set_their_pubkey(bob.pubkey)
        bob.set_their_pubkey(alice.pubkey)

        assert alice.get_decimals() == bob.get_decimals()

    def test_sas_invalid_commitment(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device,
        )
        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys["ed25519"],
            alice_device,
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification()
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        alice.receive_accept_event(accept_event)

        alice_key = {
            "sender": alice_id,
            "content": alice.share_key()
        }

        key_event = KeyVerificationKey.from_dict(alice_key)
        assert isinstance(key_event, KeyVerificationKey)
        bob.receive_key_event(key_event)
        assert bob.state == SasState.key_received

        bob_key = {
            "sender": bob_id,
            "content": bob.share_key()
        }

        bob_key["content"]["key"] = alice.pubkey

        key_event = KeyVerificationKey.from_dict(bob_key)
        assert isinstance(key_event, KeyVerificationKey)
        alice.receive_key_event(key_event)
        assert alice.state == SasState.canceled

    def test_sas_mac(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device,
        )
        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device_id,
            bob_keys["ed25519"],
            alice_device,
            start_event
        )

        with pytest.raises(LocalProtocolError):
            alice.accept_sas()

        alice.set_their_pubkey(bob.pubkey)
        bob.set_their_pubkey(alice.pubkey)

        alice.state = SasState.key_received
        bob.state = SasState.key_received

        with pytest.raises(LocalProtocolError):
            alice.get_mac()

        alice.accept_sas()
        alice_mac = {
            "sender": alice_id,
            "content": alice.get_mac()
        }

        mac_event = KeyVerificationMac.from_dict(alice_mac)
        assert isinstance(mac_event, KeyVerificationMac)
        assert not bob.verified

        bob.receive_mac_event(mac_event)
        assert bob.state == SasState.mac_received
        assert not bob.verified

        bob.accept_sas()
        assert bob.verified

    def test_sas_cancelation(self):
        alice = Sas(
            alice_id,
            alice_device_id,
            alice_keys["ed25519"],
            bob_device,
        )
        assert not alice.canceled

        with pytest.raises(LocalProtocolError):
            alice.get_cancelation()

        alice.cancel()
        assert alice.canceled

        cancelation = alice.get_cancelation()
        assert cancelation == {
            "transaction_id": alice.transaction_id,
            "code": "m.user",
            "reason": "Canceled by user"
        }
