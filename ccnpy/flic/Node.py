#  Copyright 2019 Marc Mosko
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


class Node(ccnpy.TlvType):
    __type = 0x0010

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, node_data=None, hash_groups=None):
        """

        :param node_data: (optional) ccnpy.flic.NodeData
        :param hash_groups: A single HashGroup or a list of HashGroups
        """
        ccnpy.TlvType.__init__(self)
        if node_data is not None and not isinstance(node_data, ccnpy.flic.NodeData):
            raise TypeError("node_data must be ccnpy.flic.NodeData")

        if hash_groups is None:
            raise ValueError("hash_groups must not be None")

        if not isinstance(hash_groups, list) or len(hash_groups) == 0:
            raise TypeError("hash_groups must be a list of one or more ccnpy.flic.HashGroup")

        self._node_data = node_data
        self._hash_groups = hash_groups

        inner_tlvs = [self._node_data]
        inner_tlvs.extend(self._hash_groups)
        self._tlv = ccnpy.Tlv(self.class_type(), inner_tlvs)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return "Node(%r, %r)" % (self._node_data, self._hash_groups)

    def node_data(self):
        return self._node_data

    def hash_groups(self):
        return self._hash_groups

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        node_data = None
        hash_groups = []

        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if tlv.type() == ccnpy.flic.NodeData.class_type():
                assert node_data is None
                node_data = ccnpy.flic.NodeData.parse(inner_tlv)

            elif tlv.type() == ccnpy.flic.HashGroup.class_type():
                hash_group = ccnpy.flic.HashGroup.parse(inner_tlv)
                hash_groups.append(hash_group)

            else:
                raise RuntimeError("Unsupported packet TLV type %r" % tlv.type())

        return cls(node_data=node_data, hash_groups=hash_groups)
