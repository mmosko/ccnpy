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
from ..core.Tlv import Tlv
from ..core.TlvType import TlvType


class SubtreeSize(TlvType):
    __type = 0x0001

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, size):
        TlvType.__init__(self)
        self._size = size
        self._tlv = Tlv.create_uint64(self.class_type(), self._size)

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "SubtreeSize: %r" % self._size

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def size(self):
        return self._size

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value_as_number())

    def serialize(self):
        return self._tlv.serialize()
