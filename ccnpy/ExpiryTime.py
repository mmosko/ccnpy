# Copyright 2019 Marc Mosko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime

import ccnpy


class ExpiryTime(ccnpy.TlvType):
    def __init__(self, timestamp):
        """
        """
        ccnpy.TlvType.__init__(self, ccnpy.TlvType.T_EXPIRY)
        self._timestamp = timestamp
        self._tlv = ccnpy.Tlv.create_uint64(self.type_number(), self._timestamp)

    def __eq__(self, other):
        return self.timestamp() == other.timestamp()

    @classmethod
    def deserialize(cls, tlv):
        if tlv.type() != ccnpy.TlvType.T_EXPIRY:
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        timestamp = tlv.value_as_number()
        return cls(timestamp)

    def serialize(self):
        return self._tlv.serialize()

    def timestamp(self):
        return self._timestamp

    def datetime(self):
        return datetime.utcfromtimestamp(self._timestamp)
