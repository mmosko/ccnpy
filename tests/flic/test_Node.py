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
import unittest

import ccnpy
from ccnpy.flic import Node


class test_Node(unittest.TestCase):
    def test_serialize(self):
        nd = ccnpy.flic.NodeData(subtree_size=ccnpy.flic.SubtreeSize(1000))

        h1 = ccnpy.HashValue(1, array.array('B', [1, 2]))
        h2 = ccnpy.HashValue(2, array.array('B', [3, 4]))
        h3 = ccnpy.HashValue(3, array.array('B', [5, 6]))
        p1 = ccnpy.flic.Pointers([h1, h2])
        p2 = ccnpy.flic.Pointers([h3])
        gd = ccnpy.flic.GroupData(subtree_size=ccnpy.flic.SubtreeSize(0x0234))

        hg1 = ccnpy.flic.HashGroup(group_data=gd, pointers=p1)
        hg2 = ccnpy.flic.HashGroup(pointers=p2)

        node = Node(node_data=nd, hash_groups=[hg1, hg2])
        actual = node.serialize()

        expected = array.array("B", [0, 2, 0, 66,
                                     # NodeData
                                     0, 1, 0, 12,
                                     0, 1, 0,  8, 0, 0, 0, 0, 0, 0, 0x03, 0xE8,
                                     # HashGroup 1
                                     0, 2, 0,  32,
                                     # Group Data
                                     0, 1, 0, 12,
                                     0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 2, 0x34,
                                     # Pointers
                                     0, 2, 0, 12,
                                     0, 1, 0, 2, 1, 2,
                                     0, 2, 0, 2, 3, 4,
                                     # Hash Group 2
                                     0,  2, 0,  10,
                                     # Pointers
                                     0, 2, 0,  6,
                                     0, 3, 0, 2, 5, 6
                                     ])
        self.assertEqual(expected, actual)

    def test_hash_values(self):
        h1 = ccnpy.HashValue(1, array.array('B', [1, 2]))
        h2 = ccnpy.HashValue(2, array.array('B', [3, 4]))
        h3 = ccnpy.HashValue(3, array.array('B', [5, 6]))
        p1 = ccnpy.flic.Pointers([h1, h2])
        p2 = ccnpy.flic.Pointers([h3])
        gd = ccnpy.flic.GroupData(subtree_size=ccnpy.flic.SubtreeSize(0x0234))

        hg1 = ccnpy.flic.HashGroup(group_data=gd, pointers=p1)
        hg2 = ccnpy.flic.HashGroup(pointers=p2)

        node = ccnpy.flic.Node(hash_groups=[hg1, hg2])
        expected = [h1, h2, h3]
        actual = node.hash_values()
        self.assertEqual(expected, actual)
