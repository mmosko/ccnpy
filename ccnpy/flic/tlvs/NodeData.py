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
from typing import Optional, List

from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.NcDef import NcDef
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tlvs.SubtreeDigest import SubtreeDigest
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers
from ccnpy.flic.tlvs.Vendor import Vendor
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.exceptions.ParseError import ParseError


class NodeData(TlvType):
    """
    Represents metadata about a Manifest node.

        NodeData = TYPE LENGTH [SubtreeSize] [SubtreeDigest] [Locators] 0*Vendor 0*NcDef

    """

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_NODE_DATA

    def __init__(self,
                 subtree_size: Optional[SubtreeSize | int] = None,
                 subtree_digest: Optional[SubtreeDigest] = None,
                 locators: Optional[Locators] = None,
                 vendors: Optional[List[Vendor]] = None,
                 nc_defs: Optional[List[NcDef]] = None):
        """

        :param subtree_size:
        :param subtree_digest:
        :param locators:
        :param nc_defs: Name constructor definitions.  Recommend only be used in root manifest.
        """
        TlvType.__init__(self)

        if isinstance(subtree_size, int):
            subtree_size = SubtreeSize(subtree_size)

        if subtree_size is not None and not isinstance(subtree_size, SubtreeSize):
            raise TypeError("subtree_size, if present, must be SubtreeSize")

        if subtree_digest is not None and not isinstance(subtree_digest, SubtreeDigest):
            raise TypeError("subtree_digest, if present, must be SubtreeDigest")

        if locators is not None and not isinstance(locators, Locators):
            raise TypeError(f"locators, if present, must be LocatorList, got {type(locators)}")

        if vendors is not None and len(vendors) == 0:
            vendors = None

        self._subtree_size = subtree_size
        self._subtree_digest = subtree_digest
        self._locators = locators
        self._vendors = vendors
        self._nc_defs = nc_defs if nc_defs is not None else []

        tlvs = []
        if self._subtree_size is not None:
            tlvs.append(self._subtree_size)

        if self._subtree_digest is not None:
            tlvs.append(self._subtree_digest)

        if self._locators is not None:
            tlvs.append(self._locators)

        if self._nc_defs is not None and len(self._nc_defs) > 0:
            tlvs.extend(self._nc_defs)

        if self._vendors is not None and len(self._vendors) > 0:
            tlvs.extend(self._vendors)

        self._tlv = Tlv(self.class_type(), tlvs)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "NodeData: {%r, %r, %r, %r, %r}" % (self._subtree_size, self._subtree_digest, self._locators, self._nc_defs, self._vendors)

    def subtree_size(self):
        return self._subtree_size

    def subtree_digest(self):
        return self._subtree_digest

    def locators(self):
        return self._locators

    def vendor_tags(self):
        return self._vendors

    def nc_defs(self) -> Optional[List[NcDef]]:
        return self._nc_defs

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        subtree_size = subtree_digest = locators = None
        vendors = []
        nc_defs = []

        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == SubtreeSize.class_type():
                assert subtree_size is None
                subtree_size = SubtreeSize.parse(inner_tlv)
            elif inner_tlv.type() == SubtreeDigest.class_type():
                assert subtree_digest is None
                subtree_digest = SubtreeDigest.parse(inner_tlv)
            elif inner_tlv.type() == Locators.class_type():
                assert locators is None
                locators = Locators.parse(inner_tlv)
            elif inner_tlv.type() == NcDef.class_type():
                nc_defs.append(NcDef.parse(inner_tlv))
            elif inner_tlv.type() == Vendor.class_type():
                vendors.append(Vendor.parse(inner_tlv))
            else:
                raise ParseError("Unsupported NodeData TLV type %r" % inner_tlv)

        return cls(subtree_size=subtree_size, subtree_digest=subtree_digest, locators=locators,
                   vendors=vendors, nc_defs=nc_defs)
