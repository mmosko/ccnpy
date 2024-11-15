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
from ccnpy.core.Name import NameComponent
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class SuffixComponentType(TlvType):
    """
    Size of all application data immediately under the Group (i.e. via direct pointers).

        SuffixComponentType = TYPE 2 2OCTET
    """

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_SUFFIX_TYPE

    def __init__(self, value):
        TlvType.__init__(self)
        if not (0 <= value <= 0xFFFF):
            raise ValueError("SuffixComponentType must be a 2-byte integer")
        self._value = value
        self._tlv = Tlv.create_uint16(self.class_type(), self._value)

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "LeafSize: %02X" % self._value

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def value(self):
        return self._value

    def create_name_component(self, data: int) -> NameComponent:
        return NameComponent(self._value, Tlv.number_to_array(data))

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value_as_number())

    def serialize(self):
        return self._tlv.serialize()
