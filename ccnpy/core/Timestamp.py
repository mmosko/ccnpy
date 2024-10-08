#  Copyright 2024 Marc Mosko
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from abc import ABC
from datetime import datetime, UTC

from .Tlv import Tlv
from .TlvType import TlvType


class Timestamp(TlvType, ABC):
    """
    base class for ExpiryTime and SignatureTime.

    Because it does not implement all the abstract methods in TlvType, this
    is an abstract intermediate class.
    """
    @classmethod
    def from_datetime(cls, dt):
        return cls(round(dt.timestamp(), 3))

    def __init__(self, timestamp):
        """
        :param timestamp: Python datetime timestamp (seconds float)
        """
        TlvType.__init__(self)
        self._timestamp = timestamp
        self._tlv = Tlv.create_uint64(self.class_type(), self.milliseconds())
        self._wire_format = self._tlv.serialize()

    def __eq__(self, other):
        return self.timestamp() == other.timestamp()

    def __repr__(self):
        return "%r: %r" % (self.__class__.__name__, self.datetime().isoformat())

    def __len__(self):
        return len(self._tlv)

    def __iter__(self):
        self._offset = 0
        return self

    def __next__(self):
        if self._offset == len(self._wire_format):
            raise StopIteration

        output = self._wire_format[self._offset]
        self._offset += 1
        return output

    def serialize(self):
        return self._tlv.serialize()

    def timestamp(self):
        """
        Python timestamp (seconds float)
        :return:
        """
        return self._timestamp

    def milliseconds(self):
        """
        Python timestamp in milliseconds as integer
        :return:
        """
        msec = int(self.timestamp() * 1000)
        return msec

    def datetime(self):
        try:
            return datetime.fromtimestamp(self._timestamp, UTC)
        except ValueError:
            return datetime.fromtimestamp(0, UTC)

    @classmethod
    def now(cls):
        return cls.from_datetime(datetime.now(UTC))
