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

from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Payload import Payload
from ccnpy.core.TlvType import OctetTlvType
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class ProtocolFlags(OctetTlvType):
    """
    These are CCN/NDN flags to pass as part of the Interest.  Stored as a byte array, like Payload.
    """

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_PROTOCOL_FLAGS

    def __repr__(self):
        return "Flags: %r" % super().__repr__()
