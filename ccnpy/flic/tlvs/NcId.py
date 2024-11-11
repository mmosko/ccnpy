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


class NcId(TlvType):
    __T_NCID = 0x0010

    @classmethod
    def class_type(cls):
        return cls.__T_NCID

    def __init__(self, nc_id: int):
        TlvType.__init__(self)
        self._nc_id = nc_id
        self._tlv = Tlv(self.class_type(), Tlv.number_to_array(self._nc_id))

    def id(self) -> int:
        return self._nc_id

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return f"NCID ({self._nc_id})"

    def __eq__(self, other):
        if not isinstance(other, NcId):
            return False
        return self._nc_id == other._nc_id

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value_as_number())

    def serialize(self):
        return self._tlv.serialize()
