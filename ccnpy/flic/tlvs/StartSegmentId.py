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


from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError


class StartSegmentId(TlvType):
    """
    If using SegmentedScheme, the starting segment id for a hash group.

        StartSegmentId = TYPE LENGTH Integer
    """
    __type = 0x0013

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, value):
        TlvType.__init__(self)
        self._value = value
        self._tlv = Tlv.create_varint(self.class_type(), self._value)

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "StartSegmentId (%r)" % self._value

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def value(self):
        return self._value

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value_as_number())

    def serialize(self):
        return self._tlv.serialize()
