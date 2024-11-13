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

import array
from typing import Optional

from .HashValue import HashValue
from .Name import Name
from .Tlv import Tlv


class Link:
    """
    A `Link` is not a TLV.  It is a wire-format tuple (name, keyid, digest).  When a Link is used somewhere,
    it must be enclosed in a TLV.
    """
    __T_KEYIDRESTR = 0x0002
    __T_OBJHASHRESTR = 0x0003

    """
    Serves as the base class for KeyLink and is used in LocatorList
    """
    def __init__(self, name: Optional[Name | str] = None, keyid: Optional[HashValue] = None, digest: Optional[HashValue] = None):
        """
        The Link will serialize as a list of TLVs.  It has no surrounding "link" type.  That context must be
        provided by the concrete class, like KeyLink.

        :param name:
        :param keyid: The KeyId restriction
        :param digest: The ContentObjectHash restriction
        """
        if name is not None:
            if isinstance(name, str):
                name = Name.from_uri(name)
            if not isinstance(name, Name):
                raise TypeError("name must be Name if present")

        if keyid is not None and not isinstance(keyid, HashValue):
            raise TypeError("keyid must be Hashvalue if present")

        if digest is not None and not isinstance(digest, HashValue):
            raise TypeError("digest must be Hashvalue if present")

        self._name = name
        self._keyid = keyid
        self._digest = digest
        # for iteration
        self._offset = 0

        self._wire_format = array.array("B", [])
        if self._name is not None:
            self._wire_format.extend(self._name.serialize())

        if self._keyid is not None:
            self._wire_format.extend(Tlv(self.__T_KEYIDRESTR, self._keyid).serialize())

        if self._digest is not None:
            self._wire_format.extend(Tlv(self.__T_OBJHASHRESTR, self._digest).serialize())

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "Link(%r, %r, %r)" % (self._name, self._keyid, self._digest)

    def __len__(self):
        return len(self._wire_format)

    def __iter__(self):
        self._offset = 0
        return self

    def __next__(self):
        if self._offset == len(self._wire_format):
            raise StopIteration

        output = self._wire_format[self._offset]
        self._offset += 1
        return output

    def name(self) -> Optional[Name]:
        return self._name

    def keyid(self) -> Optional[HashValue]:
        return self._keyid

    def digest(self) -> Optional[HashValue]:
        return self._digest

    def serialize(self):
        return self._wire_format

    @classmethod
    def deserialize(cls, buffer):
        """
        The concrete class parses a TLV and passes the tlv.value() to this method

        :param buffer:
        :return: A list of TLVs
        """
        name = keyid = digest = None

        offset = 0
        while offset < len(buffer):
            tlv = Tlv.deserialize(buffer[offset:])
            offset += len(tlv)
            if tlv.type() == Name.class_type():
                assert name is None
                name = Name.parse(tlv)
            elif tlv.type() == cls.__T_KEYIDRESTR:
                assert keyid is None
                inner_tlv = Tlv.deserialize(tlv.value())
                keyid = HashValue.parse(inner_tlv)
            elif tlv.type() == cls.__T_OBJHASHRESTR:
                assert digest is None
                inner_tlv = Tlv.deserialize(tlv.value())
                digest = HashValue.parse(inner_tlv)
            else:
                raise ValueError("Unsupported TLV %r" % tlv)
        return cls(name=name, keyid=keyid, digest=digest)
