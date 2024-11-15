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
from typing import Optional

from ccnpy.core.Link import Link
from ccnpy.core.Name import Name
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class Locator(TlvType):
    """
    A `Link` is not a TLV.  The Locator type encapsulates a Link inside a TLV.
    """

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_LINK

    @classmethod
    def from_uri(cls, uri: str):
        """
        A convenience method when making a singleton Locator
        """
        return cls(Link(name=Name.from_uri(uri)))

    @classmethod
    def from_name(cls, name: Name):
        """
        A convenience method when making a singleton Locator
        """
        return cls(Link(name=name))

    def __init__(self, link):
        """

        :param links: A ccnpy.core.Link
        """
        TlvType.__init__(self)

        if not isinstance(link, Link):
            raise TypeError("link must be ccnpy.core.Link")

        if link.name() is None:
            raise ValueError('A locator link must have a name')

        self._link = link
        self._tlv = Tlv(self.class_type(), link.serialize())

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "Locator: %r" % self._link

    def serialize(self):
        return self._tlv.serialize()

    def name(self) -> Name:
        return self._link.name()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("tlv type %r must be %r" % (tlv.type(), cls.class_type()))

        link = Link.deserialize(tlv.value())
        return cls(link)
