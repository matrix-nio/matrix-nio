#!/usr/bin/env python3

import asyncio
import json
import os
import sys
import getpass

from nio import AsyncClient, LoginResponse

CONFIG_FILE = "restore_login_config.json"

# Check out main() below to see how it's done.


def write_details_to_disk(resp: LoginResponse, home_server) -> None:
    """Writes the required login details to disk so we can log in later without
    using a password.

    Arguments:
        resp {LoginResponse} -- the successful client login response.
        home_server -- the name of the homeserver, e.g. "https://matrix.example.org"
    """
    # open the config file in write-mode
    with open(CONFIG_FILE, "w") as f:
        # write the login details to disk
        json.dump(
            {
                "home_server": home_server,  # e.g. "https://matrix.example.org"
                "access_token": resp.access_token,  # long cryptographic access token
                "device_id": resp.device_id,  # device ID, 10 uppercase letters
                "user_id": resp.user_id  # e.g. "@user:example.org"
            },
            f
        )


async def main() -> None:

    # If there are no previously-saved credentials, we'll use the password
    if not os.path.exists(CONFIG_FILE):
        print("First time use. Did not find credential file. Asking for homeserver, user, and password to create credential file.")
        home_server = "https://matrix.example.org"
        home_server = input(f"Enter your homeserver: [{home_server}] ")
        if not (home_server.startswith("https://")
                or home_server.startswith("https://")):
            home_server = "https://" + home_server
        user_id = "@user:example.org"
        user_id = input(f"Enter your full user ID: [{user_id}] ")
        client = AsyncClient(home_server, user_id)
        pw = getpass.getpass()
        resp = await client.login(pw)
        # check that we logged in succesfully
        if (isinstance(resp, LoginResponse)):
            write_details_to_disk(resp, home_server)
        else:
            print(f"homeserver = \"{home_server}\"; user = \"{user_id}\"")
            print(f"Failed to log in: {resp}")
            sys.exit(1)

        print(
            "Logged in using a password. Credentials were stored.",
            "Try running the script again to login with credentials (an access token)."
        )

    # Otherwise the config file exists, so we'll use the stored credentials
    else:
        # open the file in read-only mode
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            client = AsyncClient(config['home_server'])
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
