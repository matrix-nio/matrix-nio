import asyncio
import json
import os
import sys

from nio import AsyncClient, LoginResponse

CONFIG_FILE = "restore_login_config.json"

# Check out main() below to see how it's done.

def write_details_to_disk(resp: LoginResponse) -> None:
    """Writes the required login details to disk so we can log in later without
    using a password.

    Arguments:
        resp {LoginResponse} -- the successful client login response.
    """
    # open the config file in write-mode
    with open(CONFIG_FILE, "w") as f:
        # write the login details to disk
        json.dump(
            {
            "access_token": resp.access_token,
            "device_id": resp.device_id,
            "user_id": resp.user_id
            },
            f
        )


async def send_example(client: AsyncClient, room_id: str) -> None:
    await client.room_send(
        room_id=room_id,
        message_type="m.room.message",
        content = {
            "msgtype": "m.text",
            "body": "Hello world!"
        }
    )


async def main() -> None:
    client = AsyncClient("https://matrix.example.org", "@alice:example.org")

    # If there are no previously-saved credentials, we'll use the password
    if not os.path.exists(CONFIG_FILE):
        resp = await client.login("hunter2")
        # check that we logged in succesfully
        if (isinstance(resp, LoginResponse)):
            write_details_to_disk(resp)
        else:
            print(f"Failed to log in: {resp}")
            sys.exit(1)

        print(
            "Logged in using a password.",
            "Try running the script again to login with an access token"
        )

    # Otherwise the config file exists, so we'll use the stored credentials
    else:
        # open the file in read-only mode
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            client.access_token = config['access_token']
            client.user_id = config['user_id']
            client.device_id = config['device_id']

        # Now we can send messages as the user
        await send_example(client, "!myfavouriteroomid:example.org")
        print("Logged in using stored credentials")

    # Either way we're logged in here, too
    await client.close()

asyncio.get_event_loop().run_until_complete(main())
