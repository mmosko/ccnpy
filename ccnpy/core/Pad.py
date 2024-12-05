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
from ccnpy.core.TlvType import TlvType, OctetTlvType
from ccnpy.exceptions.CannotParseError import CannotParseError


class Pad(OctetTlvType):
    __T_PAD = 0x0FFE

    @classmethod
    def class_type(cls):
        return cls.__T_PAD

    def __init__(self, length: int):
        """
        Create a PAD TLV of `length` 0's.  It is OK to have a 0-length PAD, when ends up
        adding only 4 bytes (for the T and L).
        """
        assert length >= 0
        super().__init__(length * [0])

    def __repr__(self):
        return "PAD: len %d" % len(self)

    @classmethod
    def parse(cls, tlv):
        result = super().parse(tlv)
        for b in result.value_bytes():
            if b != 0:
                raise ValueError(f'The value of a PAD must all be 0s, got: {result.value()}')
        return result
