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
from typing import List

from .Locator import Locator
from ..core.Link import Link
from ..core.Tlv import Tlv
from ..core.TlvType import TlvType
from ..exceptions.CannotParseError import CannotParseError


class Locators(TlvType):
    """
    Represents a list of Locators (links).

        Locators = TYPE LENGTH 1*Link
    """
    __type = 0x0003

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, locators: List[Locator]):
        """

        :param final:
        :param locators: a list of Links
        """
        TlvType.__init__(self)

        if len(locators) == 0:
            raise RuntimeError("Locators must have at least 1 link")

        self._locators = locators
        self._tlv = Tlv(self.class_type(), self._locators)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return f"Locators: {self._locators}"

    def locators(self):
        return self._locators

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv)

        locators = []
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            try:
                link = Locator.parse(inner_tlv)
                locators.append(link)
            except CannotParseError:
                raise

        return cls(locators=locators)