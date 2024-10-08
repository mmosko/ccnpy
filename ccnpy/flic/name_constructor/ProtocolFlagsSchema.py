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
from typing import Optional

from .NcSchema import NcSchema
from .ProtocolFlags import ProtocolFlags
from ...core.Tlv import Tlv
from ...exceptions.CannotParseError import CannotParseError


class ProtocolFlagsSchema(NcSchema):

    def __init__(self, flags: Optional[ProtocolFlags] = None):
        NcSchema.__init__(self)
        self._flags = flags
        self._tlv = Tlv(self.class_type(), self._flags)

    def __len__(self):
        return len(self._tlv)

    def serialize(self):
        return self._tlv.serialize()

    def flags(self) -> Optional[ProtocolFlags]:
        return self._flags

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        flags = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            try:
                flags = ProtocolFlags.parse(inner_tlv)
            except CannotParseError:
                raise

        return cls(flags=flags)
    