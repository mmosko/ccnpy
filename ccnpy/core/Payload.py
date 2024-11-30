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


class Payload(OctetTlvType):
    __T_PAYLOAD = 0x0001

    @classmethod
    def class_type(cls):
        return cls.__T_PAYLOAD

    def __repr__(self):
        return "PAYLOAD: %r" % super().__repr__()
