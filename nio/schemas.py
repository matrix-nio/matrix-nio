# -*- coding: utf-8 -*-

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

from __future__ import unicode_literals

from jsonschema import FormatChecker, validate


RoomRegex = "^![a-zA-Z0-9]+:.+$"


@FormatChecker.cls_checks("user_id", ValueError)
def check_user_id(value):
    # type: (str) -> bool
    if not value.startswith("@"):
        raise ValueError("UserIDs start with @")

    if ":" not in value:
        raise ValueError(
            "UserIDs must have a domain component, seperated by a :"
        )

    return True


def validate_json(instance, schema):
    validate(instance, schema, format_checker=FormatChecker())


class Schemas(object):
    room_message = {
        "type": "object",
        "properties": {
            "content": {
                "type": "object",
                "properties": {
                    "msgtype": {"type": "string"},
                },
                "required": ["msgtype"]
            }
        }
    }

    room_message_text = {
        "type": "object",
        "properties": {
            "msgtype": {"type": "string", "const": "m.text"},
            "content": {
                "type": "object",
                "properties": {
                    "body": {"type": "string"},
                    "formatted_body": {"type": "string"},
                    "format": {"type": "string"}
                },
                "required": ["body"]
            }
        }
    }

    room_message_emote = {
        "type": "object",
        "properties": {
            "msgtype": {"type": "string", "const": "m.emote"},
            "content": {
                "type": "object",
                "properties": {
                    "body": {"type": "string"},
                    "formatted_body": {"type": "string"},
                    "format": {"type": "string"}
                },
                "required": ["body"]
            }
        }
    }

    redacted_event = {
        "type": "object",
        "properties": {
            "unsigned": {
                "type": "object",
                "properties": {
                    "redacted_because": {
                        "type": "object",
                        "properties": {
                            "sender": {
                                "type": "string",
                                "format": "user_id"
                            },
                            "content": {
                                "type": "object",
                                "properties": {
                                    "reason": {"type": "string"}
                                }
                            }
                        },
                        "required": ["sender", "content"]
                    },
                },
                "required": ["redacted_because"]
            }
        },
        "required": ["unsigned"]
    }

    login = {
        "type": "object",
        "properties": {
            "user_id": {"type": "string", "format": "user_id"},
            "device_id": {"type": "string"},
            "access_token": {"type": "string"}
        },
        "required": ["user_id", "device_id", "access_token"]
    }

    error = {
        "type": "object",
        "properties": {
            "error": {"type": "string"},
            "errcode": {"type": "string"}
        },
        "required": ["error", "errcode"]
    }

    sync = {
        "type": "object",
        "properties": {
            "device_one_time_keys_count": {"type": "object"},
            "next_batch": {"type": "string"},
            "rooms": {
                "type": "object",
                "properties": {
                    "invite": {
                        "type": "object",
                        "patternProperties": {
                            RoomRegex: {"type": "object"}
                        },
                        "additionalProperties": False
                    },
                    "join": {
                        "type": "object",
                        "patternProperties": {
                            RoomRegex: {"type": "object"}
                        },
                        "additionalProperties": False
                    },
                    "leave": {
                        "type": "object",
                        "patternProperties": {
                            RoomRegex: {"type": "object"}
                        },
                        "additionalProperties": False
                    }
                }
            },
            "to_device": {
                "type": "object",
                "properties": {"events": {"type": "array"}}
            }
        },
        "required": [
            "next_batch",
            "device_one_time_keys_count",
            "rooms",
            "to_device"
        ]
    }

    room_event = {
        "type": "object",
        "properties": {
            "event_id": {"type": "string"},
            "sender": {"type": "string", "format": "user_id"},
            "type": {"type": "string"}
        },
        "required": ["event_id", "sender", "type"]
    }

    room_timeline = {
        "type": "object",
        "properties": {
            "events": {"type": "array"},
            "limited": {"type": "boolean"},
            "prev_batch": {"type": "string"}
        },
        "required": ["events", "limited", "prev_batch"]
    }

    olm_event = {
        "type": "object",
        "properties": {
            "sender": {"type": "string", "format": "user_id"},
            "sender_device": {"type": "string"},
            "keys": {
                "type": "object",
                "properties": {
                    "ed25519": {"type": "string"}
                }
            },
            "recipient": {"type": "string", "format": "user_id"},
            "recipient_keys": {
                "type": "object",
                "properties": {
                    "ed25519": {"type": "string"}
                }
            },
            "type": {"type": "string"},
            "content": {"type": "object"}
        },
        "required": [
            "type",
            "sender",
            "sender_device",
            "keys",
            "recipient",
            "recipient_keys",
            "content"
        ]
    }

    room_key_event = {
        "type": "object",
        "properties": {
            "sender": {"type": "string", "format": "user_id"},
            "sender_device": {"type": "string"},
            "type": {"type": "string", "enum": ["m.room_key"]},
            "content": {
                "type": "object",
                "properties": {
                    "algorithm": {"type": "string"},
                    "room_id": {"type": "string", "format": "room_id"},
                    "session_id": {"type": "string"},
                    "session_key": {"type": "string"},
                    "chain_index": {"type": "integer"},
                },
                "required": [
                    "algorithm",
                    "room_id",
                    "session_id",
                    "session_key"
                ]
            }
        },
        "required": [
            "type",
            "sender",
            "sender_device",
            "content"
        ]
    }

    room_canonical_alias = {
        "type": "object",
        "properties": {
            "sender": {"type": "string", "format": "user_id"},
            "type": {"type": "string"},
            "content": {
                "type": "object",
                "properties": {
                    "alias": {"type": "string"},
                },
                "required": ["alias"]
                }
            },
        "required": [
            "type",
            "sender",
            "content"
        ]
    }

    room_name = {
        "type": "object",
        "properties": {
            "sender": {"type": "string", "format": "user_id"},
            "type": {"type": "string"},
            "content": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": ["name"]
                }
            },
        "required": [
            "type",
            "sender",
            "content"
        ]
    }

    room_topic = {
        "type": "object",
        "properties": {
            "sender": {"type": "string", "format": "user_id"},
            "type": {"type": "string"},
            "content": {
                "type": "object",
                "properties": {
                    "topic": {"type": "string"},
                },
                "required": ["topic"]
                }
            },
        "required": [
            "type",
            "sender",
            "content"
        ]
    }
