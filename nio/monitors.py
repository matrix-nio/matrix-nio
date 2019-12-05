# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2019 miruka <miruka@disroot.org>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Thread
from typing import Callable, Deque, Optional


@dataclass
class TransferMonitor:
    """Get statistics, pause or cancel a running upload.

    A ``TransferMonitor`` object can be passed to the
    ``AsyncClient.upload()`` methods;
    the methods will then update the object's statistics while the transfer
    is running.

    The transfer can also be paused or cancelled using the object.

    Args:
        total_size (int): Size in bytes of the data to transfer.

        on_transfered (Callable[[int], None], optional): A callback to call
            with the new value of ``transfered`` when it changes.

        on_speed_changed (Callable[[float], None], optional): A callback to
            call with the new value of ``average_speed`` when it changes.

        update_rate (int, optional): How many times per second
            ``average_speed`` should be updated. Defaults to ``10``.

    Attributes:
        average_speed (float): An average number of how many bytes
            are being transfered per second.

        start_time (datetime): The date when the ``TransferMonitor` object
            was created.

        end_time (datetime, optional): The date when the transfer was
            completed, or ``None`` if it is still running.

        pause (bool): Indicates to methods using this object if the transfer
            should be paused. ``False`` by default.

        cancel (bool): When set to True, stop updating statistics and
            indicate to methods using this object that they should raise
            a ``TransferCancelledError``.
    """
    # TODO: tell that this can be used for downloads too once implemented.

    total_size:       int                               = field()
    on_transfered:    Optional[Callable[[int], None]]   = None
    on_speed_changed: Optional[Callable[[float], None]] = None
    update_rate:      int                               = 4

    average_speed: float              = field(init=False, default=0.0)
    start_time:    datetime           = field(init=False)
    end_time:      Optional[datetime] = field(init=False, default=None)
    pause:         bool               = field(init=False, default=False)
    cancel:        bool               = field(init=False, default=False)

    _transfered:  int          = field(init=False, default=0)
    _past_speeds: Deque[float] = field(init=False)
    _updater:     Thread       = field(init=False)

    def __post_init__(self) -> None:
        self.start_time   = datetime.now()
        self._past_speeds = Deque(maxlen=self.update_rate)
        self._start_update_loop()

    def _start_update_loop(self) -> None:
        """Start a Thread running ``_update_loop()``."""

        self._updater = Thread(target=self._update_loop, daemon=True)
        self._updater.start()

    def _update_loop(self) -> None:
        """A loop to constantly update the average transfer speed.

        The speed is averaged over a period of one second.
        The loop exits when the transfer is done or cancelled.
        """

        previous_transfered = 0
        previous_date       = datetime.now()

        while not self.done and not self.cancel:
            transfered = self.transfered

            self._past_speeds.append(
                (transfered - previous_transfered) /
                (datetime.now() - previous_date).total_seconds(),
            )

            previous_speed = self._past_speeds[-1]

            self.average_speed = sum(self._past_speeds) / self.update_rate

            previous_transfered = transfered
            previous_date       = datetime.now()

            if self.average_speed != previous_speed and self.on_speed_changed:
                self.on_speed_changed(self.average_speed)

            time.sleep(1 / self.update_rate)

        if self.done and not self.average_speed:
            # Transfer was fast enough to end before we had time to calculate
            self.average_speed = self.total_size

    @property
    def transfered(self) -> int:
        """Number of currently transfered bytes."""
        return self._transfered

    @transfered.setter
    def transfered(self, size: int) -> None:
        old_value        = self._transfered
        self._transfered = size

        if size >= self.total_size:
            self.end_time = datetime.now()

        if size != old_value and self.on_transfered:
            self.on_transfered(size)

    @property
    def percent_done(self) -> float:
        """Percentage of completion for the transfer."""
        return self.transfered / self.total_size * 100

    @property
    def remaining(self) -> int:
        """Number of remaining bytes to transfer."""
        return self.total_size - self.transfered

    @property
    def spent_time(self) -> timedelta:
        """Time elapsed since the transfer started."""
        return (self.end_time or datetime.now()) - self.start_time

    @property
    def remaining_time(self) -> Optional[timedelta]:
        """Estimated remaining time to complete the transfer.

        Returns None (for infinity) if the current transfer speed is 0 bytes/s.
        """
        if not self.average_speed:
            return None

        return timedelta(seconds=self.remaining / self.average_speed)

    @property
    def done(self) -> bool:
        """Whether the transfer is finished."""
        return bool(self.end_time)
