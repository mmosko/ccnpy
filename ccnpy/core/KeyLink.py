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

from .Link import Link
from .Tlv import Tlv
from .TlvType import TlvType


class KeyLink(TlvType):

    __T_KEYLINK = 0x000E

    @classmethod
    def class_type(cls):
        return cls.__T_KEYLINK

    def __init__(self, link: Link):
        TlvType.__init__(self)
        self._link = link
        self._tlv = Tlv(self.class_type(), link)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "KeyLink: {link: %r}" % self._link

    def __len__(self):
        return len(self._tlv)

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise TypeError("TLV type %r expected %r" % (tlv.type(), cls.class_type()))

        link = Link.deserialize(tlv.value())
        return cls(link)
