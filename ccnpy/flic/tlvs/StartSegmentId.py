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


from ccnpy.core.TlvType import IntegerTlvType
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class StartSegmentId(IntegerTlvType):
    """
    If using SegmentedScheme, the starting segment id for a hash group.

        StartSegmentId = TYPE LENGTH Integer
    """

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_START_SEGMENT_ID

    def __init__(self, value):
        super().__init__(value)

    def __repr__(self):
        return "StartSegmentId (%r)" % self._value
