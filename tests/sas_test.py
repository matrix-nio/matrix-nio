import pytest

from nio.crypto import Sas, SasState
from nio.exceptions import LocalProtocolError
from nio.events import KeyVerificationStart
from helpers import faker

alice_id = faker.mx_id()
alicd_device = faker.device_id()
alice_keys = faker.olm_key_pair()

bob_id = faker.mx_id()
bob_device = faker.device_id()
bob_keys = faker.olm_key_pair()


class TestClass(object):
    def test_sas_creation(self):
        alice = Sas(
            alice_id,
            alicd_device,
            alice_keys["ed25519"],
            bob_id,
            bob_device
        )

        with pytest.raises(LocalProtocolError):
            alice.accept_verification()

    def test_sas_start(self):
        alice = Sas(
            alice_id,
            alicd_device,
            alice_keys["ed25519"],
            bob_id,
            bob_device
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
            bob_device,
            bob_keys["ed25519"],
            start_event
        )

        assert bob.state == SasState.started
