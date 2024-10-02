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

import ccnpy
from .Timestamp import Timestamp


class ExpiryTime(Timestamp):
    __T_EXPIRY = 0x0006

    @classmethod
    def class_type(cls):
        return cls.__T_EXPIRY

    def __init__(self, timestamp):
        """
        :param timestamp: Python datetime timestamp (seconds float)
        """
        Timestamp.__init__(self, timestamp)

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        msec = tlv.value_as_number()
        timestamp = msec / 1000.0
        return cls(timestamp)
