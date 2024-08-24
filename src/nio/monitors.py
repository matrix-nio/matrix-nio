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
from typing import Callable, List, Optional


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

        on_transferred (Callable[[int], None], optional): A callback to call
            with the new value of ``transferred`` when it changes.

        on_speed_changed (Callable[[float], None], optional): A callback to
            call with the new value of ``average_speed`` when it changes.

        speed_period (float, optional): How many previous seconds are
            considered to calculate ``average_speed``. Defaults to ``10``.
            Lower values makes ``average_speed`` more accurate, but less smooth
            and more susceptible to speed fluctuations.

    Attributes:
        average_speed (float): An average number of how many bytes
            are being transferred per second.

        start_time (datetime): The date when the ``TransferMonitor` object
            was created.

        end_time (datetime, optional): The date when the transfer was
            completed, or ``None`` if it is still running.

        pause (bool): Indicates to methods using this object if the transfer
            should be paused. ``False`` by default.
            At this time, servers don't handle pausing uploads well and
            will end up dropping the connection after some time.

        cancel (bool): When set to True, stop updating statistics and
            indicate to methods using this object that they should raise
            a ``TransferCancelledError``.
    """

    # TODO: tell that this can be used for downloads too once implemented.

    total_size: int = field()
    on_transferred: Optional[Callable[[int], None]] = None
    on_speed_changed: Optional[Callable[[float], None]] = None
    speed_period: float = 10

    average_speed: float = field(init=False, default=0.0)
    start_time: datetime = field(init=False)
    end_time: Optional[datetime] = field(init=False, default=None)
    pause: bool = field(init=False, default=False)
    cancel: bool = field(init=False, default=False)

    _transferred: int = field(init=False, default=0)
    _updater: Thread = field(init=False)
    _last_transferred_sizes: List[int] = field(init=False)

    _update_loop_sleep_time: float = field(default=1)

    def __post_init__(self) -> None:
        self.start_time = datetime.now()
        self._last_transferred_sizes = []
        self._start_update_loop()

    def _start_update_loop(self) -> None:
        """Start a Thread running ``self._update_loop()``."""

        self._updater = Thread(target=self._update_loop, daemon=True)
        self._updater.start()

    def _update_loop(self) -> None:
        """Calculate and update the average transfer speed every second."""

        times_we_got_data = 0

        while not self.done and not self.cancel:
            if self.pause:
                time.sleep(self._update_loop_sleep_time / 10)
                continue

            bytes_transferred_this_second = sum(self._last_transferred_sizes)
            self._last_transferred_sizes.clear()

            previous_speed = self.average_speed

            consider_past_secs = min(times_we_got_data, self.speed_period) or 1

            self.average_speed = max(
                0,
                self.average_speed * (consider_past_secs - 1) / consider_past_secs
                + bytes_transferred_this_second / consider_past_secs,
            )

            if self.average_speed != previous_speed and self.on_speed_changed:
                self.on_speed_changed(self.average_speed)

            if bytes_transferred_this_second:
                times_we_got_data += 1

            time.sleep(self._update_loop_sleep_time)

        if self.done and not self.average_speed:
            # Transfer was fast enough to end before we had time to calculate
            self.average_speed = self.total_size

    @property
    def transferred(self) -> int:
        """Number of currently transferred bytes."""
        return self._transferred

    @transferred.setter
    def transferred(self, size: int) -> None:
        old_value = self._transferred
        self._transferred = size

        self._last_transferred_sizes.append(size - old_value)

        if size >= self.total_size:
            self.end_time = datetime.now()

        if size != old_value and self.on_transferred:
            self.on_transferred(size)

    @property
    def percent_done(self) -> float:
        """Percentage of completion for the transfer."""
        return self.transferred / self.total_size * 100

    @property
    def remaining(self) -> int:
        """Number of remaining bytes to transfer."""
        return self.total_size - self.transferred

    @property
    def spent_time(self) -> timedelta:
        """Time elapsed since the transfer started."""
        return (self.end_time or datetime.now()) - self.start_time

    @property
    def remaining_time(self) -> Optional[timedelta]:
        """Estimated remaining time to complete the transfer.

        Returns None (for infinity) if the current transfer speed is 0 bytes/s,
        or the remaining time is so long it would cause an OverflowError.
        """
        try:
            return timedelta(seconds=self.remaining / self.average_speed)
        except (ZeroDivisionError, OverflowError):
            return None

    @property
    def done(self) -> bool:
        """Whether the transfer is finished."""
        return bool(self.end_time)
