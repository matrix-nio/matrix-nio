"""Nio Event Builders Module.

This module provides classes to easily create event dictionaries that
can be used with the clients's ``room_send()`` method, or ``room_create()``'s
``inital_state`` argument.
It also provides classes for some direct events such as to-device messages.
"""

from .event_builder import EventBuilder
from .state_events import *
from .direct_messages import *
