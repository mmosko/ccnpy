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

import ccnpy


class ValidationPayload(ccnpy.TlvType):
    def __init__(self, payload):
        """
        """
        ccnpy.TlvType.__init__(self, ccnpy.TlvType.T_VALIDATION_PAYLOAD)
        self._payload = payload
        self._tlv = ccnpy.Tlv(self.type_number(), self._payload)

    def __eq__(self, other):
        return self.payload() == other.payload()

    @classmethod
    def deserialize(cls, tlv):
        if tlv.type() != ccnpy.TlvType.T_VALIDATION_PAYLOAD:
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value())

    def serialize(self):
        return self._tlv.serialize()

    def payload(self):
        return self._payload
