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


import ccnpy
import ccnpy.flic


class NodeData(ccnpy.TlvType):
    __type = 0x0001
    __subtree_digest_type = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, subtree_size=None, subtree_digest=None, locators=None):
        """

        :param subtree_size:
        :param subtree_digest:
        :param locators:
        """
        ccnpy.TlvType.__init__(self)

        if isinstance(subtree_size, int):
            subtree_size = ccnpy.flic.SubtreeSize(subtree_size)

        if subtree_size is not None and not isinstance(subtree_size, ccnpy.flic.SubtreeSize):
            raise TypeError("subtree_size, if present, must be ccnpy.flic.SubtreeSize")

        if subtree_digest is not None and not isinstance(subtree_digest, ccnpy.HashValue):
            raise TypeError("subtree_digest, if present, must be ccnpy.HashValue")

        if locators is not None and not isinstance(locators, ccnpy.flic.LocatorList):
            raise TypeError("locators, if present, must be ccnpy.flic.LocatorList")

        self._subtree_size = subtree_size
        self._subtree_digest = subtree_digest
        self._locators = locators

        tlvs = []
        if self._subtree_size is not None:
            tlvs.append(subtree_size)

        if self._subtree_digest is not None:
            tlvs.append(ccnpy.Tlv(NodeData.__subtree_digest_type, self._subtree_digest))

        if self._locators is not None:
            tlvs.append(self._locators)

        self._tlv = ccnpy.Tlv(self.class_type(), tlvs)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "NodeData: {%r, %r, %r}" % (self._subtree_size, self._subtree_digest, self._locators)

    def subtree_size(self):
        return self._subtree_size

    def subtree_digest(self):
        return self._subtree_digest

    def locators(self):
        return self._locators

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        subtree_size = subtree_digest = locators = None

        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ccnpy.flic.SubtreeSize.class_type():
                assert subtree_size is None
                subtree_size = ccnpy.flic.SubtreeSize.parse(inner_tlv)
            elif inner_tlv.type() == cls.__subtree_digest_type:
                assert subtree_digest is None
                subtree_digest = ccnpy.HashValue.deserialize(inner_tlv.value())
            elif inner_tlv.type() == ccnpy.flic.LocatorList.class_type():
                assert locators is None
                locators = ccnpy.flic.LocatorList.parse(inner_tlv)
            else:
                raise RuntimeError("Unsupported NodeData TLV type %r" % inner_tlv)

        return cls(subtree_size=subtree_size, subtree_digest=subtree_digest, locators=locators)
