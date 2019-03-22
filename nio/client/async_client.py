# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
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


from typing import (
    Any,
    Dict,
    Optional,
    Tuple,
    Union,
)

from json.decoder import JSONDecodeError
from aiohttp import ClientSession, ContentTypeError

from ..api import Api
from ..responses import (
    LoginResponse,
    LoginError,
    SyncResponse,
    SyncError,
)
from . import Client, ClientConfig


class AsyncClient(Client):
    """An async IO matrix client.

    Args:
        homeserver (str): The URL of the homeserver which we want to connect
            to.
        user (str, optional): The user which will be used when we log in to the
            homeserver.
        device_id (str, optional): An unique identifier that distinguishes
            this client instance. If not set the server will provide one after
            log in.
        store_path (str, optional): The directory that should be used for state
            storeage.
        config (ClientConfig, optional): Configuration for the client.
        ssl (bool/ssl.SSLContext, optional): SSL validation mode. None for
            default SSL check (ssl.create_default_context() is used), False
            for skip SSL certificate validation connection.
        proxy (str, optional): The proxy that should be used for the HTTP
            connection.

    Example:
            >>> client = AsyncClient("https://example.org", "example")
            >>> login_response = client.login("hunter1")

    """

    def __init__(
            self,
            homeserver,     # type: str
            user="",        # type: str
            device_id="",   # type: Optional[str]
            store_path="",  # type: Optional[str]
            config=None,    # type: Optional[ClientConfig]
            ssl=None,       # type: Optional[bool]
            proxy=None,     # type: Optional[str]
    ):
        # type: (...) -> None
        self.homeserver = homeserver
        self.client_session = None  # type: Optional[ClientSession]

        self.ssl = ssl
        self.proxy = proxy

        super().__init__(user, device_id, store_path, config)

    async def _create_response(self, response_class, transport_response):
        try:
            parsed_dict = await transport_response.json()
        except (JSONDecodeError, ContentTypeError):
            parsed_dict = {}

        response = response_class.from_dict(parsed_dict)
        response.transport_response = transport_response
        return response

    async def login(self, password, device_name=""):
        # type: (str, str) -> Union[LoginResponse, LoginError]
        """Login to the homeserver.

        Args:
            password (str): The user's password.
            device_name (str): A display name to assign to a newly-created
                device. Ignored if the logged in device corresponds to a
                known device.

        Returns either a `LoginResponse` if the request was successful or
        a `LoginError` if there was an error with the request.
        """
        if not self.client_session:
            self.client_session = ClientSession()

        method, path, data = Api.login(
            self.user,
            password,
            device_name=device_name,
            device_id=self.device_id
        )

        async with self.client_session.request(
                method,
                self.homeserver + path,
                data=data,
                ssl=self.ssl,
                proxy=self.proxy
        ) as resp:
            response = await self._create_response(LoginResponse, resp)
            self.receive_response(response)
            return response

    async def sync(
            self,
            timeout=None,  # type: Optional[int],
            sync_filter=None    # type: Optional[Dict[Any, Any]]
    ):
        # type: (...) -> Tuple[SyncResponse, SyncError]
        """Synchronise the client's state with the latest state on the server.

        Args:
            timeout(int, optional): The maximum time that the server should
                wait for new events before it should return the request
                anyways, in milliseconds.
            filter (Dict[Any, Any], optional): A filter that should be used for
                this sync request.

        Returns either a `SyncResponse` if the request was successful or
        a `SyncError` if there was an error with the request.
        """
        method, path = Api.sync(
            self.access_token,
            since=self.next_batch,
            timeout=timeout,
            filter=sync_filter
        )

        async with self.client_session.request(
                method,
                self.homeserver + path,
                data=None,
                ssl=self.ssl,
                proxy=self.proxy
        ) as resp:
            response = await self._create_response(SyncResponse, resp)
            self.receive_response(response)
            return response

    async def close(self):
        """Close the underlying http session."""
        await self.client_session.close()
        self.client_session = None
