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
from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.core.HashValue import HashValue
from ccnpy.flic.HashGroupBuilder import HashGroupBuilder
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.NodeData import NodeData
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.StartSegmentId import StartSegmentId
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class NodeTest(CcnpyTestCase):
    def _create_node(self):
        nd = NodeData(subtree_size=SubtreeSize(1000))

        h1 = HashValue(1, array.array('B', [1, 2]))
        h2 = HashValue(2, array.array('B', [3, 4]))
        h3 = HashValue(3, array.array('B', [5, 6]))
        p1 = Pointers([h1, h2])
        p2 = Pointers([h3])
        gd = GroupData(subtree_size=SubtreeSize(0x0234))

        hg1 = HashGroup(group_data=gd, pointers=p1)
        hg2 = HashGroup(pointers=p2)

        return Node(node_data=nd, hash_groups=[hg1, hg2])

    def test_serialize(self):
        node = self._create_node()
        actual = node.serialize()

        expected = array.array("B", [
                                     0, TlvNumbers.T_NODE, 0, 54,
                                     # NodeData
                                     0, TlvNumbers.T_NODE_DATA, 0, 6,
                                     0, TlvNumbers.T_SUBTREE_SIZE, 0,  2, 0x03, 0xE8,
                                     # HashGroup 1
                                     0, TlvNumbers.T_HASH_GROUP, 0,  26,
                                     # Group Data
                                     0, TlvNumbers.T_GROUP_DATA, 0, 6,
                                     0, TlvNumbers.T_SUBTREE_SIZE, 0, 2, 2, 0x34,
                                     # Pointers
                                     0, TlvNumbers.T_PTRS, 0, 12,
                                     0, 1, 0, 2, 1, 2,
                                     0, 2, 0, 2, 3, 4,
                                     # Hash Group 2
                                     0,  TlvNumbers.T_HASH_GROUP, 0,  10,
                                     # Pointers
                                     0, TlvNumbers.T_PTRS, 0,  6,
                                     0, 3, 0, 2, 5, 6
                                     ])
        self.assertEqual(expected, actual)

    def test_hash_values(self):
        node = self._create_node()

        h1 = HashValue(1, array.array('B', [1, 2]))
        h2 = HashValue(2, array.array('B', [3, 4]))
        h3 = HashValue(3, array.array('B', [5, 6]))
        expected = [h1, h2, h3]
        actual = node.hash_values()
        self.assertEqual(expected, actual)

    def test_hash_iterator(self):
        hg1 = HashGroup(group_data=GroupData(nc_id=NcId(1)),
                        pointers=Pointers([HashValue.create_sha256([i]) for i in range(0,4)]))
        hg2 = HashGroup(group_data=GroupData(nc_id=NcId(2)),
                        pointers=Pointers([HashValue.create_sha256([i]) for i in range(4,6)]))
        node = Node(hash_groups=[hg1, hg2])
        actual = []
        for x in node:
            actual.append(x)
        expected = [
            Node.HashIteratorValue(1, HashValue.create_sha256([0]), None),
            Node.HashIteratorValue(1, HashValue.create_sha256([1]), None),
            Node.HashIteratorValue(1, HashValue.create_sha256([2]), None),
            Node.HashIteratorValue(1, HashValue.create_sha256([3]), None),
            Node.HashIteratorValue(2, HashValue.create_sha256([4]), None),
            Node.HashIteratorValue(2, HashValue.create_sha256([5]), None)
        ]
        self.assertEqual(expected, actual)

    def test_hash_iterator_empty_first_group(self):
        hg1 = HashGroup(group_data=GroupData(nc_id=NcId(1)),
                        pointers=Pointers([]))
        hg2 = HashGroup(group_data=GroupData(nc_id=NcId(2)),
                        pointers=Pointers([HashValue.create_sha256([i]) for i in range(4,6)]))
        node = Node(hash_groups=[hg1, hg2])
        actual = []
        for x in node:
            actual.append(x)
        expected = [
            Node.HashIteratorValue(2, HashValue.create_sha256([4]), None),
            Node.HashIteratorValue(2, HashValue.create_sha256([5]), None)
        ]
        self.assertEqual(expected, actual)

    def test_hash_iterator_empty_second_group(self):
        hg1 = HashGroup(group_data=GroupData(nc_id=NcId(1)),
                        pointers=Pointers([HashValue.create_sha256([i]) for i in range(0,2)]))
        hg2 = HashGroup(group_data=GroupData(nc_id=NcId(2)),
                        pointers=Pointers([]))
        node = Node(hash_groups=[hg1, hg2])
        actual = []
        for x in node:
            actual.append(x)
        expected = [
            Node.HashIteratorValue(1, HashValue.create_sha256([0]), None),
            Node.HashIteratorValue(1, HashValue.create_sha256([1]), None)
        ]
        self.assertEqual(expected, actual)

    def test_iter(self):
        hg1 = HashGroup(group_data=GroupData(nc_id=NcId(1)),
                        pointers=Pointers([HashValue.create_sha256([i]) for i in range(0,2)]))
        node = Node(hash_groups=[hg1])
        actual = []
        i = iter(node)
        for x in i:
            actual.append(x)
        expected = [
            Node.HashIteratorValue(1, HashValue.create_sha256([0]), None),
            Node.HashIteratorValue(1, HashValue.create_sha256([1]), None)
        ]
        self.assertEqual(expected, actual)

    def test_segment_id(self):
        hg1 = HashGroup(group_data=GroupData(nc_id=NcId(1), start_segment_id=StartSegmentId(10)),
                        pointers=Pointers([HashValue.create_sha256([i]) for i in range(0,2)]))
        hg2 = HashGroup(group_data=GroupData(nc_id=NcId(2), start_segment_id=StartSegmentId(0)),
                        pointers=Pointers([HashValue.create_sha256([i]) for i in range(2, 4)]))
        node = Node(hash_groups=[hg1, hg2])
        actual = []
        for x in node:
            actual.append(x)
        expected = [
            Node.HashIteratorValue(1, HashValue.create_sha256([0]), 10),
            Node.HashIteratorValue(1, HashValue.create_sha256([1]), 11),
            Node.HashIteratorValue(2, HashValue.create_sha256([2]), 0),
            Node.HashIteratorValue(2, HashValue.create_sha256([3]), 1)
        ]
        self.assertEqual(expected, actual)
