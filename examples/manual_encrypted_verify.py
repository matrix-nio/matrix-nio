import asyncio
import os
import sys
import sys
import json

from nio import (AsyncClient, ClientConfig, DevicesError, Event, LoginResponse,
                 LocalProtocolError, MatrixRoom, MatrixUser, RoomMessageText,
                 crypto, exceptions)

# This is a fully-documented example of how to do manual verification with nio,
# for when you already know the device IDs of the users you want to trust. If
# you want live verification using emojis, the process is more complicated and
# will be covered in another example.

# We're building on the restore_login example here to preserve device IDs and
# therefore preserve trust; if @bob trusts @alice's device ID ABC and @alice
# restarts this program, loading the same keys, @bob will preserve trust. If 
# @alice logged in again @alice would have new keys and a device ID XYZ, and
# @bob wouldn't trust it.

# The store is where we want to place encryption details like our keys, trusted
# devices and blacklisted devices. Here we place it in the working directory,
# but if you deploy your program you might consider /var or /opt for storage
STORE_FOLDER = "nio_store/"
# This file is for restoring login details after closing the program, so you
# can preserve your device ID. If @alice logged in every time instead, @bob
# would have to re-verify. See the retoring login example for more into.
SESSION_DETAILS_FILE = "manual_encrypted_verify.json"

# Only needed for this example, this is who @alice will securely
# communicate with. We need all the device IDs of this user so we can consider
# them "trusted". If an unknown device shows up (like @bob signs into their
# account on another device), this program will refuse to send a message in the
# room. Try it!
BOB_ID = "@bob:example.org"
BOB_DEVICE_IDS = [
    # You can find these in Riot under Settings > Security & Privacy.
    # They may also be called "session IDs". You'll want to add ALL of them here
    # for the one other user in your encrypted room
    "URDEVICEID",
    ]

# the ID of the room you want your bot to join and send commands in.
# This can be a direct message or room; Matrix treats them the same
ROOM_ID = "!myfavouriteroom:example.org"

ALICE_USER_ID = "@alice:example.org"
ALICE_HOMESERVER = "https://matrix.example.org"
ALICE_PASSWORD = "hunter2"

def write_details_to_disk(resp: LoginResponse) -> None:
    """Writes login details to disk so that we can restore our session later
    without logging in again and creating a new device ID.

    Arguments:
        resp {LoginResponse} -- the successful client login response.
    """
    with open(SESSION_DETAILS_FILE, "w") as f:
        json.dump({
            "access_token": resp.access_token,
            "device_id": resp.device_id,
            "user_id": resp.user_id
        }, f)


async def main() -> None:
    """A very simple encrypted nio application.
    """
    # If the store location doesn't exist, we'll make it
    if not os.path.isdir(STORE_FOLDER):
        os.mkdir(STORE_FOLDER)

    # By setting `store_sync_tokens` to true, we'll save sync tokens to our
    # store every time we sync, thereby preventing reading old, previously read
    # events on each new sync.
    # For more info, check out https://matrix-nio.readthedocs.io/en/latest/nio.html#asyncclient
    config = ClientConfig(store_sync_tokens=True)
    client = AsyncClient(
        ALICE_HOMESERVER,
        ALICE_USER_ID,
        store_path=STORE_FOLDER,
        config=config
    )

    # restore the previous session if we can, otherwise login
    if os.path.exists(SESSION_DETAILS_FILE) and os.path.isfile(SESSION_DETAILS_FILE):
        try:
            with open(SESSION_DETAILS_FILE, "r") as f:
                config = json.load(f)
                client.access_token = config['access_token']
                client.user_id = config['user_id']
                client.device_id = config['device_id']

                # This loads our verified/blacklisted devices and our keys
                client.load_store()
                print(f"Logged in using stored credentials: {client.user_id} on {client.device_id}")

        except IOError as err:
            print(f"Couldn't load session from file. Logging in. Error: {err}")
        except json.JSONDecodeError as err:
            print(f"Couldn't read JSON file; overwriting")

    if not client.user_id or not client.access_token or not client.device_id:
        resp = await client.login(ALICE_PASSWORD)
        if isinstance(resp, LoginResponse):
            print("Logged in using a password; saving details to disk")
            write_details_to_disk(resp)
        else:
            print(f"Failed to log in: {resp}")
            sys.exit(1)

    # If your room isn't public, you'll need to invite this user before
    # it joins the room
    await client.join(ROOM_ID)
    await client.sync(full_state=True)

    room = client.rooms[ROOM_ID]
    print(f"Room {room.name} is encrypted: {room.encrypted}" )

    # nio will transparently encrypt the message for us but other users cannot
    # read it as we have not shared our keys and haven't received the keys of
    # anyone else.
    await client.room_send(
        room_id=ROOM_ID,
        message_type="m.room.message",
        content = {
            "msgtype": "m.text",
            "body": "An encrypted message you cannot read"
        }
    )

    if (client.should_upload_keys):
        # We'll upload our public keys for others to use in encrypting messages
        await client.keys_upload()
    
    if (client.should_query_keys):
        # Since encryption is a two way street, we'll get the public keys
        # of the other members of our encrypted rooms
        await client.keys_query()

    # In practice, you want to have a list of previously-known device IDs for
    # each user you want to trust. Here we require that list as a global var
    for device_id in BOB_DEVICE_IDS:
        # When we join an encrypted room and then run sync, we populate our
        # client.device_store; if we _only_ joined the room or _only_ synced,
        # client.device_store would be empty.

        # This is the set of known OlmDevices for @bob, a member of an encrypted
        # room we're in. OlmDevices are devices they've signed in with that we
        # know about
        olm_device = client.device_store[BOB_ID][device_id]
        client.verify_device(olm_device)
        print(f"Trusting {device_id} for user {BOB_ID}")

    # In this case, we'll trust _all_ of our own devices. NOTE that this is
    # a SUPER BAD IDEA in practice, but for the purpose of this example
    # I think it'll be easier since you may end up creating lots of sessions for
    # @alice as you play with the script

    # Note that client.devices() returns either a DeviceResponse or DeviceError.
    # In this example, we're implicitly assuming that we get a DeviceResponse
    # back, but you probably want to catch errors.
    device_resp = await client.devices()
    for device in device_resp.devices:
        # we can't explictly trust the device @alice is currently using
        if device.id == client.device_id:
            continue

        olm_device = client.device_store[client.user_id][device.id]
        client.verify_device(olm_device)
        print(f"Trusting {device.id} for user {client.user_id}")

    # Now we send an encrypted message that @bob can read, although it will
    # appear to be "unverified" when they see it, because @bob has not verified
    # the device @alice is sending from.
    # We'll leave that as an excercise for the reader.
    try:
        await client.room_send(
            room_id=ROOM_ID,
            message_type="m.room.message",
            content = {
                "msgtype": "m.text",
                "body": "Hello, this message is encrypted"
            }
        )
    except exceptions.OlmUnverifiedDeviceError as err:
        print(f"WHOOPS: {err} Looks like you didn't add all the devices!")
        print("These are all known devices:")
        device_store: crypto.DeviceStore = client.device_store
        [print(f"\t{device.user_id}\t {device.device_id}\t {device.trust_state}\t  {device.display_name}") for device in device_store]
        sys.exit(1)

    # That's it! This program just verified another users device and sent an
    # encrypted message that only the two could read. Now go forth and prosper!

    await client.close()

asyncio.get_event_loop().run_until_complete(main())
