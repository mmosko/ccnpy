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
from .DisplayFormatter import DisplayFormatter
from .Tlv import Tlv
from .TlvType import TlvType


class ValidationPayload(TlvType):
    __T_VALIDATION_PAYLOAD = 0x0004

    @classmethod
    def class_type(cls):
        return cls.__T_VALIDATION_PAYLOAD

    def __init__(self, payload):
        """
        """
        TlvType.__init__(self)
        self._payload = payload
        self._tlv = Tlv(self.class_type(), self._payload)

    def __eq__(self, other):
        return self.payload() == other.payload()

    def __repr__(self):
        return "ValPld: %r" % DisplayFormatter.hexlify(self._payload)

    def __len__(self):
        return len(self._tlv)

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value())

    def serialize(self):
        return self._tlv.serialize()

    def payload(self):
        return self._payload
