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

from jsonschema import validate, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError
from typing import *


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


class Response(object):
    pass


class ErrorResponse(Response):
    def __init__(self, message, code=""):
        # type: (str, Optional[str]) -> None
        self.message = message
        self.code = code

    def __str__(self):
        # type: () -> str
        return "Error: {}".format(self.message)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> ErrorResponse
        schema = {
            "type": "object",
            "properties": {
                "error": {"type": "string"},
                "errcode": {"type": "string"}
            },
            "required": ["error", "errcode"]
        }

        try:
            validate(parsed_dict, schema)
        except (SchemaError, ValidationError) as e:
            return cls("Unknown error")

        return cls(parsed_dict["error"], parsed_dict["errcode"])


class LoginResponse(Response):
    def __init__(self, user_id, device_id, access_token):
        # type: (str, str, str) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.access_token = access_token

    def __str__(self):
        # type: () -> str
        return "Logged in as {}, device id: {}.".format(
            self.user_id,
            self.device_id
        )

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[LoginResponse, ErrorResponse]
        schema = {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "format": "user_id"},
                "device_id": {"type": "string"},
                "access_token": {"type": "string"}
            },
            "required": ["user_id", "device_id", "access_token"]
        }

        try:
            validate_json(parsed_dict, schema)
        except (SchemaError, ValidationError) as e:
            return ErrorResponse.from_dict(parsed_dict)

        return cls(parsed_dict["user_id"],
                   parsed_dict["device_id"],
                   parsed_dict["access_token"])
