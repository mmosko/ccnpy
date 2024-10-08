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

import array

from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError


class Payload(TlvType):
    __T_PAYLOAD = 0x0001

    @classmethod
    def class_type(cls):
        return cls.__T_PAYLOAD

    def __init__(self, value):
        TlvType.__init__(self)

        if isinstance(value, list):
            value = array.array("B", value)

        self._value = value
        self._tlv = Tlv(self.class_type(), self._value)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return "PAYLOAD: %r" % DisplayFormatter.hexlify(self._value)

    def value(self):
        return self._value

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value())
