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
from typing import Deque, Optional


@dataclass
class TransferMonitor:
    total_size:  int  = field()
    update_rate: int  = 10
    pause:       bool = False
    cancel:      bool = False

    average_speed: float              = field(init=False, default=0.0)
    start_time:    datetime           = field(init=False)
    end_time:      Optional[datetime] = field(init=False, default=None)

    _transfered:  int          = field(init=False, default=0)
    _past_speeds: Deque[float] = field(init=False)
    _updater:     Thread       = field(init=False)

    def __post_init__(self) -> None:
        self.start_time   = datetime.now()
        self._past_speeds = Deque(maxlen=self.update_rate)

        self._updater = Thread(target=self._update_loop, daemon=True)
        self._updater.start()

    def _update_loop(self) -> None:
        previous_transfered = 0
        previous_date       = datetime.now()

        while not self.done and not self.cancel:
            transfered = self.transfered

            self._past_speeds.append(
                (transfered - previous_transfered) /
                (datetime.now() - previous_date).total_seconds(),
            )

            self.average_speed = sum(self._past_speeds) / self.update_rate

            previous_transfered = transfered
            previous_date       = datetime.now()

            time.sleep(1 / self.update_rate)

        if self.done and not self.average_speed:
            # Transfer was fast enough to end before we had time to calculate
            self.average_speed = self.total_size

    @property
    def transfered(self) -> int:
        return self._transfered

    @transfered.setter
    def transfered(self, size: int) -> None:
        self._transfered = size

        if size >= self.total_size:
            self.end_time = datetime.now()

    @property
    def percent_done(self) -> float:
        return self.transfered / self.total_size * 100

    @property
    def remaining(self) -> int:
        return self.total_size - self.transfered

    @property
    def spent_time(self) -> timedelta:
        return (self.end_time or datetime.now()) - self.start_time

    @property
    def remaining_time(self) -> Optional[timedelta]:
        if not self.average_speed:
            return None

        return timedelta(seconds=self.remaining / self.average_speed)

    @property
    def done(self) -> bool:
        return bool(self.end_time)
