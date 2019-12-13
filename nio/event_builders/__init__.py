"""Nio Event Builders Module.

This module provides classes to easily create event dictionaries that
can be used with the clients's ``room_send()`` method, or ``room_create()``'s
``inital_state`` argument.
It also provides classes for some direct events such as to-device messages.
"""

from .state_events import *
from .direct_messages import *


# TODO: use abc.ABC when we drop py2
class EventBuilder(object):
    """The base class for event builders, should not be instancied."""

    def as_dict(self):
        """Format the event as a dictionary, to be sent to the server."""
        pass
