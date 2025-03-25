#!/usr/bin/env python3

import asyncio
import os

from nio import (
    AsyncClient,
    AsyncClientConfig,
    LoginResponse,
)

DIR = os.path.dirname(__file__)


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

    response = await client.login(password, device_name=device_name)

    if isinstance(response, LoginResponse):
        # "Logged in as @alice:example.org device id: RANDOMDID"
        print(response)
    else:
        raise Exception(f"login failed: {response}")

    # If you made a new room and haven't joined as that user, you can use
    # await client.join("your-room-id")

    msg_resp = await client.room_send(
        # Watch out! If you join an old room you'll see lots of old messages
        room_id="!my-fave-room:example.org",
        message_type="m.room.message",
        content={"msgtype": "m.text", "body": "Hello world!"},
    )
    print(msg_resp)

    try:
        await client.sync_forever()
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
