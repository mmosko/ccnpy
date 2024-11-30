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
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class Vendor(TlvType):
    @classmethod
    def class_type(cls):
        return TlvNumbers.T_ORG

    def __init__(self, pen: int, payload):
        TlvType.__init__(self)

        if pen < 0 or pen > 0xFFFFFF:
            raise ValueError("PEN must be a 3-byte integer")

        if isinstance(payload, list):
            payload = array.array("B", payload)

        self._payload = payload
        self._pen = pen

        value = Tlv.uint24_to_array(self._pen)
        value.extend(self._payload)
        self._tlv = Tlv(self.class_type(), value)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return "Vendor: pen: %r, payload: %r" % (self._pen, DisplayFormatter.hexlify(self._payload))

    def pen(self):
        return self._pen

    def payload(self):
        return self._payload

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        if len(tlv) < 3:
            raise ValueError("A Vendor TLV must have a 3-byte PEN")

        pen = Tlv.array_to_number(tlv.value()[0:3])
        payload = tlv.value()[3:]

        return cls(pen=pen, payload=payload)
