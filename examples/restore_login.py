#!/usr/bin/env python3

import asyncio
import json
import os
import sys
import getpass

from nio import AsyncClient, LoginResponse

CONFIG_FILE = "credentials.json"

# Check out main() below to see how it's done.


def write_details_to_disk(resp: LoginResponse, homeserver) -> None:
    """Writes the required login details to disk so we can log in later without
    using a password.

    Arguments:
        resp {LoginResponse} -- the successful client login response.
        homeserver -- URL of homeserver, e.g. "https://matrix.example.org"
    """
    # open the config file in write-mode
    with open(CONFIG_FILE, "w") as f:
        # write the login details to disk
        json.dump(
            {
                "homeserver": homeserver,  # e.g. "https://matrix.example.org"
                "user_id": resp.user_id,  # e.g. "@user:example.org"
                "device_id": resp.device_id,  # device ID, 10 uppercase letters
                "access_token": resp.access_token  # cryptogr. access token
            },
            f
        )


async def main() -> None:
    # If there are no previously-saved credentials, we'll use the password
    if not os.path.exists(CONFIG_FILE):
        print("First time use. Did not find credential file. Asking for "
              "homeserver, user, and password to create credential file.")
        homeserver = "https://matrix.example.org"
        homeserver = input(f"Enter your homeserver URL: [{homeserver}] ")

        if not (homeserver.startswith("https://")
                or homeserver.startswith("http://")):
            homeserver = "https://" + homeserver

        user_id = "@user:example.org"
        user_id = input(f"Enter your full user ID: [{user_id}] ")

        device_name = "matrix-nio"
        device_name = input(f"Choose a name for this device: [{device_name}] ")

        client = AsyncClient(homeserver, user_id)
        pw = getpass.getpass()

        resp = await client.login(pw, device_name=device_name)

        # check that we logged in succesfully
        if (isinstance(resp, LoginResponse)):
            write_details_to_disk(resp, homeserver)
        else:
            print(f"homeserver = \"{homeserver}\"; user = \"{user_id}\"")
            print(f"Failed to log in: {resp}")
            sys.exit(1)

        print(
            "Logged in using a password. Credentials were stored.",
            "Try running the script again to login with credentials."
        )

    # Otherwise the config file exists, so we'll use the stored credentials
    else:
        # open the file in read-only mode
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            client = AsyncClient(config['homeserver'])

            client.access_token = config['access_token']
            client.user_id = config['user_id']
            client.device_id = config['device_id']

        # Now we can send messages as the user
        room_id = "!myfavouriteroomid:example.org"
        room_id = input(f"Enter room id for test message: [{room_id}] ")

        await client.room_send(
            room_id,
            message_type="m.room.message",
            content={
                "msgtype": "m.text",
                "body": "Hello world!"
            }
        )
        print("Logged in using stored credentials. Sent a test message.")

    # Either way we're logged in here, too
    await client.close()

asyncio.get_event_loop().run_until_complete(main())
