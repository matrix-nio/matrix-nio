#!/usr/bin/env python3

import asyncio
import json
import os

from nio import (
    AsyncClient,
    AsyncClientConfig,
    InviteMemberEvent,
    LoginResponse,
    MatrixInvitedRoom,
    MatrixRoom,
    RoomMessageText,
    WhoamiResponse,
)

DIR = os.path.dirname(__file__)

TOKEN_FILE = os.path.join(DIR, "credentials.json")


async def login(client: AsyncClient, password, device_name):
    """
    if possible, restore login token.
    else login as new device.
    """
    if not os.path.isfile(TOKEN_FILE):
        # do a fresh login
        response = await client.login(password, device_name=device_name)

        if isinstance(response, LoginResponse):
            # "Logged in as @alice:example.org device id: RANDOMDID"
            print(f"success: {response}")
            login_data = {
                "user_id": response.user_id,
                "device_id": response.device_id,
                "token": response.access_token,
            }
            with open(TOKEN_FILE, "w") as fd:
                json.dump(login_data, fd)
        else:
            raise Exception(f"login failed: {response}")

    else:
        # restore previous login token
        with open(TOKEN_FILE) as fd:
            login_data = json.load(fd)

        client.restore_login(
            user_id=login_data["user_id"],
            device_id=login_data["device_id"],
            access_token=login_data["token"],
        )

        response = await client.whoami()
        if isinstance(response, WhoamiResponse):
            print(f"login restored: {response}")
        else:
            raise Exception(f"login restore failed: {response}")


async def main() -> None:
    homeserver = "https://matrix.example.org"
    user_id = "@alice:example.org"
    password = "my-secret-password"
    device_name = "AwesomeBot"

    config = AsyncClientConfig(
        store_sync_tokens=False,    # don't persist sync calls across restarts
        fill_timeline_gaps=True,    # when sync are truncated, fetch missing messages
        online_messages_only=True,  # behave like an irc bot - only handle messages seen while online
    )
    client = AsyncClient(
        homeserver=homeserver,
        user=user_id,
        store_path=os.path.join(DIR, "cryptostore"),  # directory to save encryption state
        config=config,
    )

    await login(client, password, device_name)

    # To let the bot answer to a room message
    async def message_callback(room: MatrixRoom, event: RoomMessageText) -> None:
        print(
            f"Message received in room {room.display_name}\n"
            f"{room.user_name(event.sender)} | {event.body}"
        )

        # send a message as response
        if event.sender != user_id:
            await client.room_send(
                room_id=room.room_id,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": "I received the message!"},
            )

    client.add_event_callback(message_callback, RoomMessageText)

    # To let your bot join when it is invited to a room:
    async def invite_callback(room: MatrixInvitedRoom, event: InviteMemberEvent) -> None:
        if event.state_key != user_id or event.membership != "invite":
            return
        print(f"I was invited to room {room.display_name}, and I'll join it.")
        await client.join(room.room_id)

    client.add_event_callback(invite_callback, InviteMemberEvent)

    try:
        await client.sync_forever()
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
