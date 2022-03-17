"""Nio Events Module.

The model of conversation history exposed by a Matrix server can be considered
as a list of events. The server 'linearises' the eventually-consistent event
graph of events into an 'event stream' at any given point in time:

Nio contains clases for most known Matrix Event types.
"""

from .account_data import *
from .ephemeral import *
from .invite_events import *
from .misc import *
from .presence import *
from .room_events import *
from .to_device import *
