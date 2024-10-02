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

import ccnpy.core
import ccnpy.flic


class Node(ccnpy.core.TlvType):
    __type = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, node_data=None, hash_groups=None):
        """

        :param node_data: (optional) ccnpy.flic.NodeData
        :param hash_groups: a list of HashGroups
        """
        ccnpy.core.TlvType.__init__(self)
        if node_data is not None and not isinstance(node_data, ccnpy.flic.NodeData):
            raise TypeError("node_data must be ccnpy.flic.NodeData")

        if hash_groups is None:
            raise ValueError("hash_groups must not be None")

        if not isinstance(hash_groups, list) or len(hash_groups) == 0:
            raise TypeError("hash_groups must be a list of one or more ccnpy.flic.HashGroup")

        self._node_data = node_data
        self._hash_groups = hash_groups

        self._tlv = ccnpy.core.Tlv(self.class_type(), [self._node_data, *self._hash_groups])

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        hash_values_len = len(self.hash_values())
        return "Node: {%r, %r, %r}" % (self._node_data, hash_values_len, self._hash_groups)

    def node_data(self):
        return self._node_data

    def hash_groups(self):
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
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        node_data = None
        hash_groups = []

        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.core.Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ccnpy.flic.NodeData.class_type():
                assert node_data is None
                node_data = ccnpy.flic.NodeData.parse(inner_tlv)

            elif inner_tlv.type() == ccnpy.flic.HashGroup.class_type():
                hash_group = ccnpy.flic.HashGroup.parse(inner_tlv)
                hash_groups.append(hash_group)

            else:
                raise RuntimeError("Unsupported packet TLV type %r" % inner_tlv)

        return cls(node_data=node_data, hash_groups=hash_groups)
