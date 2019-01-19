import pytest
from helpers import faker
from nio.rooms import MatrixRoom, MatrixInvitedRoom
from nio.responses import TypingNoticeEvent, RoomSummary
from nio.events import InviteNameEvent, InviteAliasEvent, InviteMemberEvent

TEST_ROOM = "!test:example.org"
BOB_ID = "@bob:example.org"

class TestClass(object):
    def _create_test_data(self):
        pass

    @property
    def new_user(self):
        return faker.mx_id(), faker.name()

    @property
    def test_room(self):
        return MatrixRoom(TEST_ROOM, BOB_ID)

    def test_room_creation(self):
        room = self.test_room
        assert room

    def test_adding_members(self):
        room = self.test_room
        assert not room.users
        room.add_member(*self.new_user)
        assert room.users
        assert room.members_synced
        assert room.member_count == 1

    def test_named_checks(self):
        room = self.test_room
        assert not room.is_named
        assert room.is_group

        room.name = "Test room"

        assert room.is_named
        assert not room.is_group

    def test_name_calculation(self):
        room = self.test_room
        assert room.display_name() == "Empty room?"
        assert room.named_room_name() == None

        room.add_member("@alice:example.org", "")
        assert room.display_name() == "@alice:example.org"

        room.add_member("@malory:example.org", "")
        assert (room.display_name() ==
                "@alice:example.org and @malory:example.org")
        room.add_member("@steve:example.org", "")
        assert (room.display_name() ==
                "@alice:example.org and 2 others")

        room.canonical_alias = "Alias for test room"
        assert room.display_name() == "Alias for test room"

        room.name = "Test room"
        assert room.display_name() == "#Test room"

    def test_machine_name(self):
        room = self.test_room
        assert room.machine_name == TEST_ROOM
        room.canonical_alias = "Alias room"
        assert room.machine_name == "Alias room"

    def test_typing_notice_event(self):
        room = self.test_room
        assert not room.typing_users

        room.handle_ephemeral_event(TypingNoticeEvent([BOB_ID]))
        assert room.typing_users == [BOB_ID]

    def test_summary_update(self):
        room = self.test_room
        assert not room.summary

        room.update_summary(RoomSummary(1, 2, []))
        assert room.member_count == 2
        assert room.summary

        room.update_summary(RoomSummary(1, 3, ["@alice:example.org"]))
        assert room.member_count == 3
        assert room.summary.heroes == ["@alice:example.org"]

    def test_invited_room(self):
        room = MatrixInvitedRoom(TEST_ROOM, BOB_ID)
        room.handle_event(InviteMemberEvent(
            "@alice:example.org",
            BOB_ID,
            {
                "membership": "invite"
            }
        ))
        assert room.inviter == "@alice:example.org"
        assert not room.name

        room.handle_event(InviteNameEvent(BOB_ID, "test name"))
        assert room.name == "test name"

        assert not room.canonical_alias
        room.handle_event(InviteAliasEvent(BOB_ID, "test alias"))
        assert room.canonical_alias == "test alias"
