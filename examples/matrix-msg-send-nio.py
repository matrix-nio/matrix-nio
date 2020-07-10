#!/usr/bin/env python3

# pylama:ignore=W605

"""matrix-msg-send-nio.py

0123456789012345678901234567890123456789012345678901234567890123456789012345678
0000000000111111111122222222223333333333444444444455555555556666666666777777777

This program on the first run creates a credentials.json file.
The credentials.json file stores: homeserver, user id,
access token, device id, and room id. On the first run
it asks some questions, creates the token and device id
and stores everything in the credentials.json file.

From the second time the program is run, and on all
future runs it will use the homeserver, user id
and access token found in the credentials file to log
into the Matrix account. Now this program can be used
to easily send simple text messages to the preconfigured room.
The messages can be provided
a) in the command line (-m or --message)
b) read from the keyboard
c) piped into the program through a pipe from stdin (|)

It supports 4 text formats:
a) text: default
b) html:  HTML formated text
c) markdown: MarkDown formatted text
d) code: used a block of fixed-sized font, idel for ASCII art or
   tables, bash outputs, etc.

Since the credentials file holds an access token it
should be protected and secured. One can use different
credential files for different users or different rooms.

Use cases for this program could be
a) a bot or part of a bot,
b) to send alerts,
c) combine it with cron to publish periodic data,
d) send yourself daily/weekly reminders via a cron job
e) a trivial way to fire off some instant messages from the command line

On creation the credentials file will always be created in the local 
directory, so the users sees it right away. This is fine if you have
only one or a few credential files, but for better maintainability
it is suggested to place your credentials files into directory
$HOME/.config/matrix-msg-send-nio.py/. When the program looks for 
a credentials file it will first look in local directory and then
as secondary choice it will look in directory 
$HOME/.config/matrix-msg-send-nio.py/.

In short: first run sets everything up, thereafter it can
be used to easily publish messages.


Dependencies:
- matrix-nio must be installed, see https://github.com/poljar/matrix-nio
  pip3 install --user --upgrade matrix-nio
- python3 package markdown must be installed to support MarkDown format
  pip3 install --user --upgrade markdown
- this file must be installed, and should have execution permissions
  chmod 755 matrix-msg-send-nio.py


Example uses:
$ matrix-msg-send-nio.py #  first run; this will configure everything
$ # this created a credentials.json file
$ # optionally, if you want you can move it to the app config directory
$ mkdir $HOME/.config/matrix-msg-send-nio.py # optional
$ mv credentials.json $HOME/.config/matrix-msg-send-nio.py/
$ # now you are ready to run program for a second time and send a msg
$ matrix-msg-send-nio.py # this will ask user for message to send
$ matrix-msg-send-nio.py --message "Hello World!" # sends provided message
$ echo "Hello World" | matrix-msg-send-nio.py # pipe input msg into program
$ matrix-msg-send-nio.py -m msg1 -m msg2 # sends 2 messages
$ matrix-msg-send-nio.py -m msg1 msg2 msg3 # sends 3 messages
$ df -h | matrix-msg-send-nio.py --code # formatting for code/tables
$ matrix-msg-send-nio.py -m "<b>BOLD</b> and <i>ITALIC</i>" --html
$ matrix-msg-send-nio.py -m "- bullet1" --markdown
$ matrix-msg-send-nio.py --credentials usr1room2 # select credentials file
$ matrix-msg-send-nio.py -m "hi" --room '!YourRoomId:example.org'
$ # some shells require the ! of the room id to be escaped with \
$ matrix-msg-send-nio.py -m "hi" --room r"\!YourRoomId:example.org"
$ matrix-msg-send-nio.py --debug # turn debugging on
$ matrix-msg-send-nio.py --help # print help

usage: matrix-msg-send-nio.py [-h] [-d] [-t CREDENTIALS] [-r ROOM]
                              [-m MESSAGE [MESSAGE ...]] [-w] [-n] [-c]

On first run this program will configure itself. On further runs this
program implements a simple Matrix sender. It sends one or multiple text
message to a Matrix room. The messages can be of format "text", "html",
"markdown" or "code".matrix-nio must be installed.

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Print debug information
  -t CREDENTIALS, --credentials CREDENTIALS
                        On first run, information about homeserver, user,
                        room id, etc. will be written to a credentials file.
                        By default, this file is "credentials.json". On
                        further runs the credentials file is read to permit
                        logging into the correct Matrix account and sending
                        messages to the preconfigured room. If this option
                        is provided, the provided file name will be used as
                        credentials file instead of the default one.
  -r ROOM, --room ROOM  Send to this room. Usually the room is provided in
                        credentials file. If provided it will use this room
                        instead the one from the credentials file. The user
                        must have access to the specified room in order to
                        send messages there. Messages cannot be sent to
                        arbitrary rooms.
  -m MESSAGE [MESSAGE ...], --message MESSAGE [MESSAGE ...]
                        Send this message. If not specified, and no input
                        piped in from stdin, then message will be read from
                        stdin, i.e. keyboard.This option can be used
                        multiple time to send multiple messages. If there is
                        data is piped into this program, then first data
                        from the pipe is published, then messages from this
                        option are published.
  -w, --html            Send message as format "HTML". If not specified,
                        message will be sent as format "TEXT". E.g. that
                        allows some text to be bold, etc. Only a subset of
                        HTML tags are accepted by Matrix.
  -n, --markdown        Send message as format "MARKDOWN". If not specified,
                        message will be sent as format "TEXT". E.g. that
                        allows sending of text formated in MarkDown
                        language.
  -c, --code            Send message as format "CODE". If not specified,
                        message will be sent as format "TEXT". If both
                        --html and --code are specified then --code takes
                        priority. This is useful for sending ASCII-art or
                        tabbed output like tables as a fixed-sized font will
                        be used for display.


For developers:
- Don't change tabbing, spacing, or formating as file is automatically
  linted with autopep8 --aggressive
- Long lines are ignored by linter
- pylama:format=pep8:linters=pep8:ignore=E501

Documentation related to this:
- https://matrix-nio.readthedocs.io/en/latest/examples.html

Originally forked from:
- https://github.com/poljar/matrix-nio/blob/master/examples/restore_login.py

"""

import asyncio
import json
import os
import sys
import select
import getpass
import argparse
import logging
import traceback
import textwrap
from markdown import markdown

from nio import AsyncClient, LoginResponse

CREDENTIALS_FILE_DEFAULT = "credentials.json"


def write_details_to_disk(resp: LoginResponse, homeserver,
                          room_id, credentialsfile) -> None:
    """Writes the required login details to disk so we can log in
    later without using a password.

    Arguments:
        resp {LoginResponse} -- successful client login response.
        homeserver -- URL of homeserver,
                      e.g. "https://matrix.example.org"
        room_id -- name of room where message will be sent to,
                   e.g. "!SomeRoomIdString:example.org"
        user must be member of the provided room
        credentialsfile -- name/path of file where to store
                           credentials information
    """
    # open the credentials file in write-mode
    with open(credentialsfile, "w") as f:
        # write the login details to disk
        json.dump(
            {
                # e.g. "https://matrix.example.org"
                "homeserver": homeserver,
                # long cryptographic access token
                "access_token": resp.access_token,
                # device ID, 10 uppercase letters
                "device_id": resp.device_id,
                # e.g. "@user:example.org"
                "user_id": resp.user_id,
                # e.g. "!SomeRoomIdString:example.org"
                "room_id": room_id
            },
            f
        )


async def main() -> None:
    """ main:

    This function check if a credentials file exists. If no, it will ask
    user questions regrading login, store the info in a newly created
    credentials file and exit.

    If a credentials file exists, it will read it, log into Matrix,
    send a message and exit.

    The credential file will be looked for the following way:
    a) if a path (e.g. "../cred.json") is specified it will be looked
       for there
    b) if only a filename without path (e.g. "cred.json") is specified
       first look in the current local directory, if found use it
    c) if only a filename without path (e.g. "cred.json") is specified
       and it cannot be found in the current local directory, then
       look for it in directory $HOME/.config/matrix-msg-send-nio.py/
    TLDR: on first run it will be written to current local directory
       or to path specified with --credentials command line argument.
       On further reads, program will look in currently local directory
       or in path specified with --credentials command line argument.
       If not found there (and only filename without path given),
       as a secondary choice program will look for it in
       directory $HOME/.config/matrix-msg-send-nio.py/
    """
    credentialsfile = pargs.credentials  # default location
    credentialsfiledir = os.path.expanduser("~/.config/" +
                                            os.path.basename(__file__) +
                                            "/")
    if (not os.path.exists(pargs.credentials)) and (
            pargs.credentials == os.path.basename(pargs.credentials)):
        # try path $HOME/.config/matrix-msg-send-nio.py/...
        credentialsfile = credentialsfiledir + pargs.credentials
    if not os.path.exists(credentialsfile):
        text = f'''
            Credential file \"{pargs.credentials}\" was not found.
            First time use? Setting up new credentials?
            Asking for homeserver, user, password and
            room id to create a credential file.'''
        print(textwrap.fill(textwrap.dedent(text).strip(), width=79))
        homeserver = "https://matrix.example.org"
        homeserver = input(f"Enter URL of your homeserver: [{homeserver}] ")
        if not (homeserver.startswith("https://")
                or homeserver.startswith("http://")):
            homeserver = "https://" + homeserver
        user_id = "@user:example.org"
        user_id = input(f"Enter your full user ID: [{user_id}] ")
        room_id = "!SomeRoomIdString:example.org"
        room_id = input(f"Enter your room ID: [{room_id}] ")
        client = AsyncClient(homeserver, user_id)
        pw = getpass.getpass()
        resp = await client.login(pw)
        # check that we logged in succesfully
        if (isinstance(resp, LoginResponse)):
            # when writing, always write to primary location (e.g. .)
            write_details_to_disk(resp, homeserver, room_id, pargs.credentials)
            text = f'''
                Log in using a password was successful.
                Credentials were stored in file \"{pargs.credentials}\".
                Run program \"{os.path.basename(__file__)}\" again to
                login with credentials and to send a message.
                If you plan on having many credential files, consider
                moving them to directory \"{credentialsfiledir}\".'''
            print(textwrap.fill(textwrap.dedent(text).strip(), width=79))
        else:
            print(
                f"homeserver=\"{homeserver}\"; user=\"{user_id}\"; "
                f"room_id=\"{room_id}\"")
            print(f"Failed to log in: {resp}")
            # sys.exit(1) # not needed, let if reach client.close()

    # Otherwise the credentials file exists, so we'll use the stored
    # credentials
    else:
        # open the file in read-only mode
        with open(credentialsfile, "r") as f:
            config = json.load(f)
            client = AsyncClient(config['homeserver'])
            client.access_token = config['access_token']
            client.user_id = config['user_id']
            client.device_id = config['device_id']
            room_id = config['room_id']
        logger.debug("Logged in using stored credentials from "
                     f"credentials file \"{credentialsfile}\".")

        # Now we can send messages as the user
        await send_messages(client, room_id)

    # Either way we're logged in here, too
    await client.close()


async def send_message(client, room_id, message):
    content = {"msgtype": "m.text"}
    if pargs.code:
        logger.debug("Sending message in format \"code\".")
        formatted_message = "<pre><code>" + message + "</code></pre>"
        content["format"] = "org.matrix.custom.html"  # add to dict
        content["formatted_body"] = formatted_message
    elif pargs.markdown:
        logger.debug("Converting message from MarkDown into HTML. "
                     "Sending message in format \"markdown\".")
        # e.g. converts from "-abc" to "<ul><li>abc</li></ul>"
        formatted_message = markdown(message)
        content["format"] = "org.matrix.custom.html"  # add to dict
        content["formatted_body"] = formatted_message
    elif pargs.html:
        logger.debug("Sending message in format \"html\".")
        formatted_message = message  # the same for the time being
        content["format"] = "org.matrix.custom.html"  # add to dict
        content["formatted_body"] = formatted_message
    else:
        logger.debug("Sending message in format \"text\".")
    content["body"] = message

    try:
        await client.room_send(
            room_id,
            message_type="m.room.message",
            content=content
        )
    except Exception:
        traceback.print_exc(file=sys.stdout)


async def send_messages(client, room_id):
    if pargs.room:
        room_id = pargs.room.replace(r'\!', '!')  # remove possible escape
        logger.debug("Room id was provided via command line. "
                     "Overwriting room id from credentials file "
                     f"with room id \"{room_id}\" "
                     "from command line.")

    if (not select.select([sys.stdin, ], [], [], 0.0)[0]) and (
            not pargs.message):
        # nothing is piped into program from stdin, and
        # no message is provided in command line
        logger.debug("No input on stdin. Nothing is being "
                     "piped into this program. No input in command line.")
        # nothing is piped into program from stdin, no -m in CLI
        # we read message from keyboard, print a prompt on stdout
        logger.debug("Reading message from keyboard")
        message = input("Enter message to send: ")
        await send_message(client, room_id, message)
        print("Message was sent.")
        return

    # there is a message in pipe or in command line
    if select.select([sys.stdin, ], [], [], 0.0)[0]:
        logger.debug("Something is piped into program from stdin.")
        logger.debug("Reading message from stdin pipe.")
        message = ""
        for line in sys.stdin:
            message += line
        logger.debug("Using data from stdin pipe as message.")
        await send_message(client, room_id, message)
        logger.debug("Message was sent.")

    # now go thru command line and send all --message messages
    if pargs.message:
        for message in pargs.message:
            logger.debug(
                "Message was provided with --message argument. "
                f"Message is \"{message}\".")
            await send_message(client, room_id, message)
            logger.debug("Message was sent.")


if __name__ == "__main__":
    logging.basicConfig()  # initialize root logger, a must
    # set log level on root
    if "DEBUG" in os.environ:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Construct the argument parser
    ap = argparse.ArgumentParser(
        description="On first run this program will configure itself. "
        "On further runs this program implements a simple Matrix sender. "
        "It sends one or multiple text message to a Matrix room. "
        "The messages can be of format \"text\", \"html\", \"markdown\" "
        "or \"code\"."
        "matrix-nio must be installed.")
    # Add the arguments to the parser
    ap.add_argument("-d", "--debug", required=False,
                    action="store_true", help="Print debug information")
    # -c is already used for --code, -t as abbreviation for "trust"
    ap.add_argument("-t", "--credentials", required=False,
                    default=CREDENTIALS_FILE_DEFAULT,
                    help="On first run, information about homeserver, "
                    "user, room id, etc. will be written to a credentials "
                    "file. By default, this file "
                    f"is \"{CREDENTIALS_FILE_DEFAULT}\". "
                    "On further runs the credentials file is read to "
                    "permit logging into the correct Matrix account "
                    "and sending messages to the preconfigured room. "
                    "If this option is provided, the provided file name "
                    "will be used as credentials file instead of the "
                    "default one. ")
    ap.add_argument("-r", "--room", required=False,
                    help="Send to this room. Usually the room is provided "
                    "in credentials file. If provided it will use this "
                    "room instead the one from the credentials file. "
                    "The user must have access to the specified room "
                    "in order to send messages there. Messages cannot "
                    "be sent to arbitrary rooms. When specifying the "
                    "room id some shells require the exclamation mark "
                    "to be escaped with a blackslash.")
    # allow multiple messages , e.g. -m "m1" "m2" or -m "m1" -m "m2"
    # messages is going to be a list of strings
    # e.g. messages=[ 'm1', 'm2' ]
    ap.add_argument("-m", "--message", required=False,
                    action="extend", nargs="+", type=str,
                    help="Send this message. If not specified, and no "
                    "input piped in from stdin, then message "
                    "will be read from stdin, i.e. keyboard."
                    "This option can be used multiple time to send "
                    "multiple messages. If there is data is piped "
                    "into this program, then first data from the "
                    "pipe is published, then messages from this "
                    "option are published.")
    # -h already used for --help, -w for "web"
    ap.add_argument("-w", "--html", required=False,
                    action="store_true", help="Send message as format "
                    "\"HTML\". If not specified, message will be sent "
                    "as format \"TEXT\". E.g. that allows some text "
                    "to be bold, etc. Only a subset of HTML tags are "
                    "accepted by Matrix.")
    # -m already used for --message, -n for "dowN"
    ap.add_argument("-n", "--markdown", required=False,
                    action="store_true", help="Send message as format "
                    "\"MARKDOWN\". If not specified, message will be sent "
                    "as format \"TEXT\". E.g. that allows sending of text "
                    "formated in MarkDown language.")
    ap.add_argument("-c", "--code", required=False,
                    action="store_true", help="Send message as format "
                    "\"CODE\". If not specified, message will be sent "
                    "as format \"TEXT\". If both --html and --code are "
                    "specified then --code takes priority. This is "
                    "useful for sending ASCII-art or tabbed output "
                    "like tables as a fixed-sized font will be used "
                    "for display.")
    pargs = ap.parse_args()
    if pargs.debug:
        # set log level on root logger
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger().info("Debug is turned on.")
    logger = logging.getLogger(os.path.basename(__file__))

    try:
        asyncio.get_event_loop().run_until_complete(main())
    except Exception:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)

# EOF
