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
from .ProtocolFlagsSchema import ProtocolFlagsSchema
from ..Locators import Locators
from ...core.Tlv import Tlv
from ...exceptions.CannotParseError import CannotParseError
from ...exceptions.ParseError import ParseError


class LocatorSchema(ProtocolFlagsSchema):

    def __init__(self, locators: Locators, flags: Optional[ProtocolFlags] = None):
        NcSchema.__init__(self)
        if locators is None or len(locators) == 0:
            raise ValueError("Locators must be a non-empty list")
        self._flags = flags
        self._locators = locators
        self._tlv = Tlv(self.class_type(), [self._locators, self._flags])

    def __len__(self):
        return len(self._tlv)

    def serialize(self):
        return self._tlv.serialize()

    def locators(self) -> Locators:
        return self._locators

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        flags = None
        locators = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ProtocolFlags.class_type():
                flags = ProtocolFlags.parse(inner_tlv)
            elif inner_tlv.type() == Locators.class_type():
                locators = Locators.parse(inner_tlv)
            else:
                raise ParseError(f'Unsupported tlv: {inner_tlv}')

        return cls(locators=locators, flags=flags)
    