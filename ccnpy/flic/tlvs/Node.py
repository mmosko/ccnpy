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

from ccnpy.flic.tlvs.HashGroup import HashGroup
from .NodeData import NodeData
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.exceptions.ParseError import ParseError
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType


class Node(TlvType):
    """
    The Node is the main data structure inside a Manifest.  It contains one or more HashGroups, which point to
    other objects.

    ```
    Node = TYPE LENGTH [NodeData] 1*HashGroup
    ```
    """
    __type = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, node_data: Optional[NodeData] = None, hash_groups: List[HashGroup] = None):
        """

        :param node_data: (optional) ccnpy.flic.NodeData
        :param hash_groups: a list of HashGroups
        """
        TlvType.__init__(self)
        self._node_data = node_data
        self._hash_groups = hash_groups

        if node_data is not None and not isinstance(node_data, NodeData):
            raise TypeError("node_data must be ccnpy.flic.NodeData")

        if hash_groups is None:
            raise ValueError("hash_groups must not be None")

        if not isinstance(hash_groups, list) or len(hash_groups) == 0:
            raise TypeError("hash_groups must be a list of one or more ccnpy.flic.HashGroup")

        self._tlv = Tlv(self.class_type(), [self._node_data, *self._hash_groups])

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        hash_values_len = len(self.hash_values())
        return "Node: {%r, %r, %r}" % (self._node_data, hash_values_len, self._hash_groups)

    def has_node_data(self) -> bool:
        return self._node_data is not None

    def node_data(self) -> Optional[NodeData]:
        return self._node_data

    def hash_groups(self) -> List[HashGroup]:
        return self._hash_groups

    def serialize(self):
        return self._tlv.serialize()

    def serialized_value(self):
        """
        The value of the Node's TLV byte array, which is used encrypted in an EncryptedNode via
        some algorithm.

        :return: byte array
        """
        return self._tlv.value()

    def node_locator(self):
        """
        A short-cut to calling node_data().locators()[0]
        :return: (node_data().locators[0], node_data.locators.final()) or (None, None)
        """
        locator = None
        final = None
        if self._node_data is not None:
            locators = self._node_data.locators()
            if locators is not None:
                final = locators.final()
                locator = locators[0]
        return locator, final

    def hash_values(self):
        """
        Return an in-order list of all pointer hash values from all hash groups
        :return: A list
        """
        hash_values = []
        for hg in self._hash_groups:
            for hv in hg.pointers():
                hash_values.append(hv)
        return hash_values

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        node_data = None
        hash_groups = []

        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == NodeData.class_type():
                assert node_data is None
                node_data = NodeData.parse(inner_tlv)

            elif inner_tlv.type() == HashGroup.class_type():
                hash_group = HashGroup.parse(inner_tlv)
                hash_groups.append(hash_group)

            else:
                raise ParseError("Unsupported inner TLV type %r" % inner_tlv)

        return cls(node_data=node_data, hash_groups=hash_groups)

    @classmethod
    def create_tlv(cls, value):
        return Tlv(cls.class_type(), value)
