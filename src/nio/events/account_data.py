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

"""nio Account data events.

Clients can store custom config data for their account on their homeserver.

This account data will be synced between different devices and can persist
across installations on a particular device.

"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from ..api import PushRuleKind
from ..schemas import Schemas
from .misc import verify, verify_or_none
from .room_events import Event

if TYPE_CHECKING:
    from ..rooms import MatrixRoom


@dataclass
class AccountDataEvent:
    """Abstract class for account data events."""

    @classmethod
    @verify(Schemas.account_data)
    def parse_event(
        cls,
        event_dict: Dict[Any, Any],
    ):
        if event_dict["type"] == "m.fully_read":
            return FullyReadEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.tag":
            return TagEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.push_rules":
            return PushRulesEvent.from_dict(event_dict)

        return UnknownAccountDataEvent.from_dict(event_dict)


@dataclass
class FullyReadEvent(AccountDataEvent):
    """Read marker location event.

    The current location of the user's read marker in a room.
    This event appears in the user's room account data for the room the marker
    is applicable for.

    Attributes:
        event_id (str): The event id the user's read marker is located
            at in the room.

    """

    event_id: str = field()

    @classmethod
    @verify(Schemas.fully_read)
    def from_dict(cls, event_dict):
        """Construct a FullyReadEvent from a dictionary."""
        content = event_dict.pop("content")
        return cls(
            content["event_id"],
        )


@dataclass
class TagEvent(AccountDataEvent):
    """Event representing the tags of a room.

       Room tags may include:

        - m.favourite for favourite rooms
        - m.lowpriority for low priority room

       A tag may have an order between 0 and 1, indicating the
       room's position towards other rooms with the same tag.

    Attributes:
        tags (Dict[str, Optional[Dict[str, float]]]): The tags of the room
        and their contents.
    """

    tags: Dict[str, Optional[Dict[str, float]]] = field()

    @classmethod
    @verify(Schemas.tags)
    def from_dict(cls, event_dict):
        """Construct a TagEvent from a dictionary."""
        content = event_dict.pop("content")
        return cls(content["tags"])


@dataclass
class PushCondition:
    """A condition for a push rule to match an event."""

    @classmethod
    def from_dict(cls, condition: Dict[str, Any]) -> PushCondition:
        cnd = condition

        if cnd["kind"] == "event_match" and "key" in cnd and "pattern" in cnd:
            return PushEventMatch(cnd["key"], cnd["pattern"])

        if cnd["kind"] == "contains_display_name":
            return PushContainsDisplayName()

        if cnd["kind"] == "room_member_count":
            return PushRoomMemberCount.from_dict(cnd)

        if cnd["kind"] == "sender_notification_permission" and "key" in cnd:
            return PushSenderNotificationPermission(cnd["key"])

        return PushUnknownCondition(cnd)

    @property
    def as_value(self) -> Dict[str, Any]:
        raise NotImplementedError

    def matches(
        self,
        event: Event,
        room: MatrixRoom,
        display_name: str,
    ) -> bool:
        """Return whether this condition holds true for a room event.

        Args:
            event (Event): The room event to check the condition for.
            room (MatrixRoom): The room that this event is part of.
            display_name (str): The display name of our own user in the room.
        """
        return False


@dataclass
class PushEventMatch(PushCondition):
    """Require a field of the event to match a glob-style pattern.

    Attributes:
        key (str): The dot-separated field of the event to match,
            e.g. ``"type"`` or ``"content.body"``.

        pattern (str): Glob-style pattern to match the field's value against.
            Patterns with no special glob characters should be treated as
            starting and ending with an asterisk.
    """

    key: str = field()
    pattern: str = field()

    @property
    def as_value(self) -> Dict[str, Any]:
        return {
            "kind": "event_match",
            "key": self.key,
            "pattern": self.pattern,
        }

    def matches(
        self,
        event: Event,
        room: MatrixRoom,
        display_name: str,
    ) -> bool:
        if self.key == "room_id":
            return fnmatchcase(room.room_id, self.pattern)

        value = event.flattened().get(self.key)

        if not isinstance(value, str):
            return False

        if self.key == "content.body":
            pattern = f"*[!a-z0-9]{self.pattern.lower()}[!a-z0-9]*"
            return fnmatchcase(f" {value.lower()} ", pattern)

        return fnmatchcase(value.lower(), self.pattern.lower())


@dataclass
class PushContainsDisplayName(PushCondition):
    """Require a message's ``content.body`` to contain our display name.

    This rule can only match unencrypted messages.
    """

    @property
    def as_value(self) -> Dict[str, Any]:
        return {"kind": "contains_display_name"}

    def matches(
        self,
        event: Event,
        room: MatrixRoom,
        display_name: str,
    ) -> bool:
        body = event.source.get("content", {}).get("body")

        if not isinstance(body, str):
            return False

        pattern = rf"(^|\W){re.escape(display_name)}(\W|$)"
        return bool(re.match(pattern, body, re.IGNORECASE))


@dataclass
class PushRoomMemberCount(PushCondition):
    """Require a certain member count for the room the event is posted in.

    Attributes:
        count (int): A number of members
        operator (str): Whether the room's member count should be
            equal (``"=="``) to ``count``, inferior (``"<"``),
            superior (``">"``), inferior or equal (``"<="``),
            or superior or equal (``">="``).
    """

    count: int = field()
    operator: str = "=="

    @classmethod
    def from_dict(cls, condition: Dict[str, Any]) -> PushRoomMemberCount:
        op, num = re.findall(r"(==|<|>|<=|>=)?([0-9.-]+)", condition["is"])[0]
        return cls(int(num), op or "==")

    @property
    def as_value(self) -> Dict[str, Any]:
        operator = "" if self.operator == "==" else self.operator
        return {"kind": "room_member_count", "is": f"{operator}{self.count}"}

    def matches(
        self,
        event: Event,
        room: MatrixRoom,
        display_name: str,
    ) -> bool:
        if self.operator == "==":
            return room.joined_count == self.count
        elif self.operator == "<":
            return room.joined_count < self.count
        elif self.operator == ">":
            return room.joined_count > self.count
        elif self.operator == "<=":
            return room.joined_count <= self.count
        else:
            return room.joined_count >= self.count


@dataclass
class PushSenderNotificationPermission(PushCondition):
    """Require the event's sender to have a high enough power level.

    Attributes:
        key (str): Which key from the ``notifications`` dict in
        power levels event
        (https://matrix.org/docs/spec/client_server/latest#m-room-power-levels)
        should be referred to as the required level for the event's sender,
        e.g. ``room``.
    """

    key: str = field()

    @property
    def as_value(self) -> Dict[str, Any]:
        return {
            "kind": "sender_notification_permission",
            "key": self.key,
        }

    def matches(
        self,
        event: Event,
        room: MatrixRoom,
        display_name: str,
    ) -> bool:
        return room.power_levels.can_user_notify(event.sender, self.key)


@dataclass
class PushUnknownCondition(PushCondition):
    """An unknown kind of push rule condition.

    Attributes:
        condition (Dict[str, Any]): The condition as a dict from the
            source event.
    """

    condition: Dict[str, Any] = field()

    @property
    def as_value(self) -> Dict[str, Any]:
        return self.condition


@dataclass
class PushAction:
    """An action to apply for a push rule when matching."""

    @classmethod
    def from_dict(cls, action: Union[str, Dict[str, Any]]) -> PushAction:
        # isinstance() to make mypy happy

        if isinstance(action, str) and action == "notify":
            return PushNotify()

        if isinstance(action, str) and action == "dont_notify":
            return PushDontNotify()

        if isinstance(action, str) and action == "coalesce":
            return PushCoalesce()

        if isinstance(action, dict) and "set_tweak" in action:
            value = action.get("value")

            if action["set_tweak"] == "sound" and value is None:
                value = "default"

            if action["set_tweak"] == "highlight" and value is None:
                value = True

            return PushSetTweak(action["set_tweak"], value)

        return PushUnknownAction(action)

    @property
    def as_value(self) -> Union[str, Dict[str, Any]]:
        raise NotImplementedError


@dataclass
class PushNotify(PushAction):
    """Cause the matching event to generate a notification."""

    @property
    def as_value(self) -> str:
        return "notify"


@dataclass
class PushDontNotify(PushAction):
    """Prevents the matching event from generating a notification."""

    @property
    def as_value(self) -> str:
        return "dont_notify"


@dataclass
class PushCoalesce(PushAction):
    """Causes multiple matching events to be joined into a single notification.

    The behavior is homeserver-dependent. Homeservers not supporting this
    action should treat it as a ``PushNotify`` action.
    """

    @property
    def as_value(self) -> str:
        return "coalesce"


@dataclass
class PushSetTweak(PushAction):
    """Set a particular tweak for the notification.

    These tweaks are defined by the Matrix specification:

    - ``sound``: The sound to be played when the notification arrives,
      e.g. a file path.
      A ``value`` of ``"default"`` means to play the client's default sound.
      A device may choose to alert the user by some other means if appropriate,
      e.g. vibration.

    - ``highlight``: Whether this message should be highlighted in the UI.
      This typically takes the form of presenting the message with a different
      color or style. The UI might also be adjusted to draw particular
      attention to the room in which the event occurred.

    Attributes:
        tweak (str): The name of the tweak to set
        value (Any): The tweak's value.
    """

    tweak: str = field()
    value: Any = None

    @property
    def as_value(self) -> Dict[str, Any]:
        return {"set_tweak": self.tweak, "value": self.value}


@dataclass
class PushUnknownAction(PushAction):
    """An unknown kind of push rule action.

    Attributes:
        action (Union[str, Dict[str, Any]]): The action as a string or dict
            from the source event.
    """

    action: Union[str, Dict[str, Any]] = field()

    @property
    def as_value(self) -> Union[str, Dict[str, Any]]:
        return self.action


@dataclass
class PushRule:
    """Rule stating how to notify the user for events matching some conditions.

    Attributes:
        kind (PushRuleKind): The kind of rule this is.

        id (str): A unique (within its ruleset) string identifying this rule.
            The ``id`` for default rules set by the server starts with a ``.``.
            For rules of ``room`` kind, this will be the room ID to match for.
            For rules of ``sender`` kind, this will be the user ID to match.

        default (bool): Whether this is a default rule set by the server,
            or one that the user created explicitly.

        enabled (bool): Whether this rule is currently enabled, or
            disabled and to be ignored.

        pattern (str): Only applies to ``content`` rules.
            The glob-style pattern to match message text against.

        conditions (List[PushCondition]):
            Only applies to ``override`` and ``underride`` rules.
            The conditions that must be true for an event in order for
            this rule to be applied to it.
            A rule with no condition always matches.

        actions (List[PushAction]):
            The actions to perform when this rule matches.
    """

    kind: PushRuleKind = field()
    id: str = field()
    default: bool = field()
    enabled: bool = True
    pattern: str = ""
    conditions: List[PushCondition] = field(default_factory=list)
    actions: List[PushAction] = field(default_factory=list)

    def matches(
        self,
        event: Event,
        room: MatrixRoom,
        display_name: str,
    ) -> bool:
        """Return whether this push rule matches a room event.

        Args:
            event (Event): The room event to match.
            room (MatrixRoom): The room that this event is part of.
            display_name (str): The display name of our own user in the room.
        """

        if not self.enabled:
            return False

        conditions = self.conditions

        if self.kind == PushRuleKind.content:
            conditions = [PushEventMatch("content.body", self.pattern)]
        elif self.kind == PushRuleKind.room:
            conditions = [PushEventMatch("room_id", self.id)]
        elif self.kind == PushRuleKind.sender:
            conditions = [PushEventMatch("sender", self.id)]

        return all(c.matches(event, room, display_name) for c in conditions)

    @classmethod
    @verify_or_none(Schemas.push_rule)
    def from_dict(cls, rule: Dict[str, Any], kind: PushRuleKind) -> PushRule:
        return cls(
            kind,
            rule["rule_id"],
            rule["default"],
            rule["enabled"],
            rule.get("pattern", ""),
            [PushCondition.from_dict(c) for c in rule.get("conditions", [])],
            [PushAction.from_dict(a) for a in rule.get("actions", [])],
        )


@dataclass
class PushRuleset:
    """A set of different kinds of push rules under a same scope.

    Attributes:
        override (List[PushRule]): Highest priority rules

        content (List[PushRule]): Rules that configure behaviors for messages
            with text matching certain patterns.

        room (List[PushRule]): Rules that configure behaviors for all messages
            in a certain room. Their ``id`` is the room's ID.

        sender (List[PushRule]): Rules that configure behaviors for all
            messages sent by a specific user. Their ``id`` is the user's ID.

        underride (List[PushRule]): Identical the ``override`` rules, but have
            a lower priority than ``content``, ``room`` and ``sender`` rules.
    """

    override: List[PushRule] = field(default_factory=list)
    content: List[PushRule] = field(default_factory=list)
    room: List[PushRule] = field(default_factory=list)
    sender: List[PushRule] = field(default_factory=list)
    underride: List[PushRule] = field(default_factory=list)

    def matching_rule(
        self,
        event: Event,
        room: MatrixRoom,
        display_name: str,
    ) -> Optional[PushRule]:
        """Return the push rule in this set that matches a room event, if any.

        Args:
            event (Event): The room event to match.
            room (MatrixRoom): The room that this event is part of.
            display_name (str): The display name of our own user in the room.
        """

        for kind in PushRuleKind:
            for rule in getattr(self, kind.value):
                if rule.matches(event, room, display_name):
                    return rule

        return None

    @classmethod
    @verify_or_none(Schemas.push_ruleset)
    def from_dict(cls, ruleset: Dict[str, Any]) -> PushRuleset:
        kwargs = {}

        for kind in PushRuleKind:
            rules = [
                PushRule.from_dict(rule_dict, kind)
                for rule_dict in ruleset.get(kind.value, [])
            ]
            # PushRule.from_dict returns None if the schema verification fails
            kwargs[kind.value] = [r for r in rules if r]

        return cls(**kwargs)

    def __bool__(self) -> bool:
        return bool(
            self.override or self.content or self.room or self.sender or self.underride,
        )


@dataclass
class PushRulesEvent(AccountDataEvent):
    """Configured push rule sets for an account. Each set belongs to a scope.

    Attributes:
        global_rules (PushRuleset): Rulesets applying to all devices
        device_rules (PushRuleset): Rulesets applying to current device only
    """

    global_rules: PushRuleset = field(default_factory=PushRuleset)
    device_rules: PushRuleset = field(default_factory=PushRuleset)

    @classmethod
    @verify(Schemas.push_rules)
    def from_dict(cls, event: Dict[str, Any]) -> PushRulesEvent:
        content = event["content"]

        return cls(
            PushRuleset.from_dict(content.get("global", {})) or PushRuleset(),
            PushRuleset.from_dict(content.get("device", {})) or PushRuleset(),
        )

    def __bool__(self) -> bool:
        return bool(self.global_rules or self.device_rules)


@dataclass
class UnknownAccountDataEvent(AccountDataEvent):
    """Account data event of an unknown type.

    Attributes:
        type (str): The type of the event.
        content (Dict): The content of the event.

    """

    type: str = field()
    content: Dict[str, Any] = field()

    @classmethod
    def from_dict(cls, event_dict):
        """Construct an UnknownAccountDataEvent from a dictionary."""
        content = event_dict.pop("content")
        return cls(event_dict["type"], content)
