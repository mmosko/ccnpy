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
from .HashValue import HashValue
from ..exceptions.CannotParseError import CannotParseError


class HashTlvType(TlvType):
    """
    A TLV that contains a HashValue.

    To avoid circular imports, HashTlvType cannot be in TlvType.py
    """
    def __init__(self, digest: HashValue):

        TlvType.__init__(self)

        if digest is None:
            raise ValueError("digest must not be None")
        if not isinstance(digest, HashValue):
            raise TypeError("digest must be HashValue")

        self._digest = digest
        self._tlv = Tlv(self.class_type(), self._digest)

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "%r" % self._digest

    def __eq__(self, other):
        if not isinstance(other, HashTlvType):
            return False
        return self._tlv == other._tlv

    def __hash__(self):
        return hash(self._tlv)
    
    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        inner_tlv = Tlv.deserialize(tlv.value())
        digest = HashValue.parse(inner_tlv)
        return cls(digest)

    def serialize(self):
        return self._tlv.serialize()

    def digest(self) -> HashValue:
        return self._digest
