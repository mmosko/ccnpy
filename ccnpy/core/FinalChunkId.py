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

from .Tlv import Tlv
from .TlvType import TlvType


class FinalChunkId(TlvType):
    __T_FINAL_CHUNK_ID = 0x0007

    @classmethod
    def class_type(cls):
        return cls.__T_FINAL_CHUNK_ID

    def __init__(self, chunk_id: int):
        TlvType.__init__(self)
        self._chunk_id = chunk_id
        self._tlv = Tlv.create_varint(self.class_type(), self._chunk_id)

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return f"FCID: {self._chunk_id}"

    def __eq__(self, other):
        if not isinstance(other, FinalChunkId):
            return False

        return self._chunk_id == other._chunk_id

    def __hash__(self):
        return self._chunk_id

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value_as_number())

    def serialize(self):
        return self._tlv.serialize()
