import pytest

from helpers import faker
from nio.events import (InviteAliasEvent, InviteMemberEvent, InviteNameEvent,
                        RoomAvatarEvent,
                        RoomCreateEvent, RoomGuestAccessEvent,
                        RoomHistoryVisibilityEvent, RoomJoinRulesEvent,
                        RoomMemberEvent, RoomNameEvent, TypingNoticeEvent,
                        Receipt, ReceiptEvent)
from nio.responses import RoomSummary
from nio.rooms import MatrixInvitedRoom, MatrixRoom

TEST_ROOM = "!test:example.org"
BOB_ID = "@bob:example.org"
ALICE_ID = "@alice:example.org"

class TestClass:
    def _create_test_data(self):
        pass

    @property
    def new_user(self):
        return faker.mx_id(), faker.name(), faker.avatar_url()

    @property
    def test_room(self):
        room = MatrixRoom(TEST_ROOM, BOB_ID)
        room.update_summary(RoomSummary(0, 0, []))
        return room

    def test_room_creation(self):
        room = self.test_room
        assert room

    def test_adding_members(self):
        room = self.test_room
        assert not room.users

        mx_id, name, avatar = self.new_user
        room.add_member(mx_id, name, avatar)
        room.summary.heroes.append(mx_id)
        room.summary.joined_member_count += 1
        assert room.users
        assert room.member_count == room.joined_count == 1
        assert room.invited_count == 0

        room.summary = None
        assert room.member_count == room.joined_count == 1
        assert room.invited_count == 0

        member = list(room.users.values())[0]
        assert member.user_id == mx_id
        assert member.display_name == name
        assert member.avatar_url == avatar

    def test_summary_details(self):
        room = self.test_room

        room.summary = None
        with pytest.raises(ValueError):
            assert room._summary_details()

        room.summary = RoomSummary(None, None, [])
        with pytest.raises(ValueError):
            assert room._summary_details()

        room.summary = RoomSummary(0, None, [])
        with pytest.raises(ValueError):
            assert room._summary_details()

        room.summary = RoomSummary(None, 0, [])
        with pytest.raises(ValueError):
            assert room._summary_details()

        room.summary = RoomSummary(0, 0, [])
        assert room._summary_details() == ([], 0, 0)

    def test_named_checks(self):
        room = self.test_room
        assert not room.is_named
        assert room.is_group

        room.name = "Test room"

        assert room.is_named
        assert not room.is_group

    def test_name_calculation_when_unnamed(self):
        room = self.test_room
        assert room.named_room_name() is None
        assert room.display_name == "Empty Room"

        # Members join

        room.add_member(BOB_ID, "Bob", None)  # us
        room.summary.joined_member_count += 1
        assert room.display_name == "Empty Room"

        room.add_member("@alice:example.org", "Alice", None)
        room.summary.heroes.append("@alice:example.org")
        room.summary.joined_member_count += 1
        assert room.display_name == "Alice"

        room.add_member("@malory:example.org", "Alice", None)
        room.summary.heroes.append("@malory:example.org")
        room.summary.joined_member_count += 1
        assert (room.display_name ==
                "Alice (@alice:example.org) and Alice (@malory:example.org)")

        room.add_member("@steve:example.org", "Steve", None)
        room.summary.heroes.append("@steve:example.org")
        room.summary.joined_member_count += 1
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org) "
                "and Steve")

        room.add_member("@carol:example.org", "Carol", None)
        room.summary.joined_member_count += 1
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org), "
                "Steve and 1 other")

        room.add_member("@dave:example.org", "Dave", None)
        room.summary.joined_member_count += 1
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org), "
                "Steve and 2 others")

        room.add_member("@erin:example.org", "Eirin", None)
        room.summary.invited_member_count += 1
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org), "
                "Steve and 3 others")

        # Members leave

        room.summary.joined_member_count = 1
        room.summary.invited_member_count = 0
        assert (room.display_name ==
                "Empty Room (had Alice (@alice:example.org), "
                "Alice (@malory:example.org) and Steve)")

        room.remove_member("@steve:example.org")
        room.summary.heroes.remove("@steve:example.org")
        assert (room.display_name ==
                "Empty Room (had Alice (@alice:example.org) and "
                "Alice (@malory:example.org))")

        room.remove_member("@malory:example.org")
        room.summary.heroes.remove("@malory:example.org")
        assert room.display_name == "Empty Room (had Alice)"

        room.remove_member("@alice:example.org")
        room.summary.heroes.remove("@alice:example.org")
        assert room.display_name == "Empty Room"

        room.remove_member("@bob:example.org")  # us
        assert not room.summary.heroes
        assert room.display_name == "Empty Room"

    def test_name_calculation_when_unnamed_no_summary(self):
        room = self.test_room
        room.summary = RoomSummary()
        assert room.named_room_name() is None
        assert room.display_name == "Empty Room"

        # Members join

        room.add_member(BOB_ID, "Bob", None)  # us
        assert room.display_name == "Empty Room"

        room.add_member("@alice:example.org", "Alice", None)
        assert room.display_name == "Alice"

        room.add_member("@malory:example.org", "Alice", None)
        assert (room.display_name ==
                "Alice (@alice:example.org) and Alice (@malory:example.org)")

        room.add_member("@steve:example.org", "Steve", None)
        room.add_member("@carol:example.org", "Carol", None)
        room.add_member("@dave:example.org", "Dave", None)
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org), "
                "Carol, Dave and Steve")

        room.add_member("@erin:example.org", "Eirin", None)
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org), "
                "Carol, Dave, Eirin and 1 other")

        room.add_member("@frank:example.org", "Frank", None)
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org), "
                "Carol, Dave, Eirin and 2 others")

        room.add_member("@gregor:example.org", "Gregor", None)
        assert (room.display_name ==
                "Alice (@alice:example.org), Alice (@malory:example.org), "
                "Carol, Dave, Eirin and 3 others")

        # Members leave

        for member in room.users.copy():
            room.remove_member(member)

        assert room.display_name == "Empty Room"

    def test_name_calculation_with_canonical_alias(self):
        room = self.test_room
        room.canonical_alias = "#test:termina.org.uk"
        assert room.display_name == "#test:termina.org.uk"

    def test_name_calculation_prefer_name_over_alias(self):
        room = self.test_room
        room.canonical_alias = "#test:termina.org.uk"
        room.name = "Test room"
        assert room.display_name == "Test room"

    def test_name_calculation_when_hash_already_prefixed(self):
        room = self.test_room

        room.name = "#test"
        assert room.display_name == "#test"

    def test_set_room_avatar(self):
        room = self.test_room
        room.room_avatar_url = "mxc://foo"
        assert room.gen_avatar_url == "mxc://foo"

    def test_room_avatar_calculation_when_no_set_avatar(self):
        room = self.test_room
        assert room.room_avatar_url is None
        assert room.summary
        assert room.is_group

        room.add_member("@bob:example.org", "Bob", "mxc://abc", True)  # us
        room.summary.joined_member_count += 1
        assert room.gen_avatar_url is None

        room.add_member("@carol:example.org", "Carol", "mxc://bar", True)
        room.summary.invited_member_count += 1
        assert room.gen_avatar_url is None
        room.summary.heroes.append("@carol:example.org")
        assert room.gen_avatar_url == "mxc://bar"

        room.name = "Test"
        assert not room.is_group
        assert room.gen_avatar_url is None
        room.name = None
        assert room.is_group
        assert room.gen_avatar_url == "mxc://bar"

        room.add_member("@alice:example.org", "Alice", "mxc://baz")
        room.summary.heroes.append("@alice:matrix.org")
        room.summary.joined_member_count += 1
        assert room.gen_avatar_url is None

    def test_room_avatar_calculation_when_no_set_avatar_no_summary(self):
        room = self.test_room
        room.summary = None
        assert room.room_avatar_url is None
        assert room.is_group

        room.add_member("@bob:example.org", "Bob", "mxc://abc", True)  # us
        assert room.gen_avatar_url is None

        room.add_member("@carol:example.org", "Carol", "mxc://bar", True)
        assert room.gen_avatar_url == "mxc://bar"

        room.name = "Test"
        assert not room.is_group
        assert room.gen_avatar_url is None
        room.name = None
        assert room.is_group
        assert room.gen_avatar_url == "mxc://bar"

        room.add_member("@alice:example.org", "Alice", "mxc://baz")
        assert room.gen_avatar_url is None

    def test_user_name_calculation(self):
        room = self.test_room
        assert room.user_name("@not_in_the_room:example.org") is None

        room.add_member("@alice:example.org", "Alice", None)
        assert room.user_name("@alice:example.org") == "Alice"
        assert room.user_name_clashes("Alice") == ["@alice:example.org"]

        room.add_member("@bob:example.org", None, None)
        assert room.user_name("@bob:example.org") == "@bob:example.org"

        room.add_member("@malory:example.org", "Alice", None)
        assert room.user_name("@alice:example.org") == "Alice (@alice:example.org)"
        assert room.user_name("@malory:example.org") == "Alice (@malory:example.org)"
        assert room.user_name_clashes("Alice") == ["@alice:example.org", "@malory:example.org"]

        room.remove_member("@alice:example.org")
        assert room.user_name("@malory:example.org") == "Alice"

        room.remove_member("@malory:example.org")
        room.add_member("@alice:example.org", None, None)
        assert room.user_name("@alice:example.org") == "@alice:example.org"
        assert room.user_name_clashes("@alice:example.org") == ["@alice:example.org"]

        room.add_member("@malory:example.org", "@alice:example.org", None)
        assert room.user_name("@alice:example.org") == "@alice:example.org"
        assert room.user_name("@malory:example.org") == "@alice:example.org (@malory:example.org)"
        assert room.user_name_clashes("@alice:example.org") == ["@alice:example.org", "@malory:example.org"]

    def test_avatar_url(self):
        room = self.test_room
        assert room.user_name("@not_in_the_room:example.org") is None
        assert room.avatar_url("@not_in_the_room:example.org") is None

        room.add_member("@alice:example.org", "Alice", "mxc://foo")
        assert room.avatar_url("@alice:example.org") == "mxc://foo"

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

    def test_read_receipt_event(self):
        """Verify that m.read ReceiptEvents update a room's read_receipt dict.

        Successive m.read receipts should replace the first receipt with the
        second.
        """
        room = self.test_room
        assert room.read_receipts == {}

        r1 = Receipt("event_id", "m.read", BOB_ID, 10)
        r2 = Receipt("event_id2", "m.read", BOB_ID, 15)

        r1_event = ReceiptEvent([r1])
        r2_event = ReceiptEvent([r2])

        room.handle_ephemeral_event(r1_event)
        assert room.read_receipts == {
            BOB_ID: r1
        }

        room.handle_ephemeral_event(r2_event)
        assert room.read_receipts == {
            BOB_ID: r2
        }

    def test_non_read_receipt_event(self):
        """Verify that non-m.read receipts don't leak into a room's read_receipt
        dict.
        """
        room = self.test_room
        room.handle_ephemeral_event(
            ReceiptEvent([
                Receipt("event_id", "m.downvoted", BOB_ID, 0)
            ])
        )
        assert room.read_receipts == {}

    def test_create_event(self):
        room = self.test_room
        assert not room.creator
        room.handle_event(
                RoomCreateEvent(
                    {
                        "event_id": "event_id",
                        "sender": BOB_ID,
                        "origin_server_ts": 0
                    },
                    BOB_ID, False
                )
        )
        assert room.creator == BOB_ID
        assert room.federate is False
        assert room.room_version == "1"

    def test_guest_access_event(self):
        room = self.test_room
        assert room.guest_access == "forbidden"
        room.handle_event(
            RoomGuestAccessEvent(
                {
                    "event_id": "event_id",
                    "sender": BOB_ID,
                    "origin_server_ts": 0
                },
                "can_join"
            )
        )
        assert room.guest_access == "can_join"

    def test_history_visibility_event(self):
        room = self.test_room
        assert room.history_visibility == "shared"
        room.handle_event(
            RoomHistoryVisibilityEvent(
                {
                    "event_id": "event_id",
                    "sender": BOB_ID,
                    "origin_server_ts": 0
                },
                "invited"
            )
        )
        assert room.history_visibility == "invited"

    def test_join_rules_event(self):
        room = self.test_room
        assert room.join_rule == "invite"
        room.handle_event(
            RoomJoinRulesEvent(
                {
                    "event_id": "event_id",
                    "sender": BOB_ID,
                    "origin_server_ts": 0
                },
                "public"
            )
        )
        assert room.join_rule == "public"

    def test_name_event(self):
        room = self.test_room
        assert not room.name
        room.handle_event(
            RoomNameEvent(
                {
                    "event_id": "event_id",
                    "sender": BOB_ID,
                    "origin_server_ts": 0
                },
                "test name"
            )
        )
        assert room.name == "test name"

    def test_room_avatar_event(self):
        room = self.test_room
        assert not room.gen_avatar_url
        room.handle_event(
            RoomAvatarEvent(
                {
                    "event_id": "event_id",
                    "sender": BOB_ID,
                    "origin_server_ts": 0
                },
                "mxc://foo"
            )
        )
        assert room.gen_avatar_url == "mxc://foo"

    def test_summary_update(self):
        room = self.test_room
        room.summary = None

        room.update_summary(RoomSummary(1, 2, []))
        assert room.invited_count == 1
        assert room.joined_count == 2
        assert room.member_count == 3
        assert room.summary

        room.update_summary(RoomSummary(1, 3, ["@alice:example.org"]))
        assert room.invited_count == 1
        assert room.joined_count == 3
        assert room.member_count == 4
        assert room.summary.heroes == ["@alice:example.org"]

    def test_invited_room(self):
        room = MatrixInvitedRoom(TEST_ROOM, BOB_ID)
        room.handle_event(InviteMemberEvent(
            {},
            "@alice:example.org",
            BOB_ID,
            "invite",
            None,
            {
                "membership": "invite"
            }
        ))
        assert room.inviter == "@alice:example.org"
        assert not room.name

        room.handle_event(InviteNameEvent({}, BOB_ID, "test name"))
        assert room.name == "test name"

        assert not room.canonical_alias
        room.handle_event(InviteAliasEvent({}, BOB_ID, "test alias"))
        assert room.canonical_alias == "test alias"

    def test_handle_member_return_value(self):
        room = self.test_room
        assert not room.users
        mx_id, name, avatar = self.new_user
        assert room.add_member(mx_id, name, avatar)
        assert not room.add_member(mx_id, name, avatar)

        assert room.remove_member(mx_id)
        assert not room.remove_member(mx_id)

    def test_user_membership_changes(self):
        invited_event = RoomMemberEvent(
            {"event_id": "event1", "sender": BOB_ID, "origin_server_ts": 1},
            ALICE_ID,
            "invite",
            None,
            {"membership": "invite", "displayname": "Alice Margarine"},
        )

        joins_event = RoomMemberEvent(
            {"event_id": "event2", "sender": ALICE_ID, "origin_server_ts": 2},
            ALICE_ID,
            "join",
            None,
            {
                "membership": "join",
                "displayname": "Alice Margatroid",
                "avatar_url": "mxc://new",
            },
        )

        leaves_event = RoomMemberEvent(
            {"event_id": "event3", "sender": ALICE_ID, "origin_server_ts": 3},
            ALICE_ID,
            "leave",
            None,
            {"membership": "leave"},
        )

        unknown_event = RoomMemberEvent(
            {"event_id": "event4", "sender": ALICE_ID, "origin_server_ts": 4},
            ALICE_ID,
            "bad_membership",
            None,
            {"membership": "bad_membership"},
        )

        room = self.test_room
        assert not room.users
        assert not room.invited_users

        # Alice is invited, accepts (her name and avatar changed) then leaves

        room.handle_membership(invited_event)
        assert set(room.users) == {ALICE_ID}
        assert set(room.invited_users) == {ALICE_ID}

        room.handle_membership(joins_event)
        assert set(room.users) == {ALICE_ID}
        assert not room.invited_users
        assert room.names["Alice Margatroid"] == [ALICE_ID]
        assert room.users[ALICE_ID].display_name == "Alice Margatroid"
        assert room.users[ALICE_ID].avatar_url == "mxc://new"


        room.handle_membership(leaves_event)
        assert not room.users
        assert not room.invited_users

        # Alice is invited and declines

        room.handle_membership(invited_event)
        assert set(room.users) == {ALICE_ID}
        assert set(room.invited_users) == {ALICE_ID}

        room.handle_membership(leaves_event)
        assert not room.users
        assert not room.invited_users

        # Alice joins without invite then leaves

        room.handle_membership(joins_event)
        assert set(room.users) == {ALICE_ID}
        assert not room.invited_users

        room.handle_membership(leaves_event)
        assert not room.users
        assert not room.invited_users

        # Ensure we get False if we handle an event that changes nothing or
        # has an unknown new membership

        assert not room.handle_membership(leaves_event)
        assert not room.handle_membership(unknown_event)
