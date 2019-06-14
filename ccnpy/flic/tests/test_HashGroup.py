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

import unittest
import array
import ccnpy
import ccnpy.flic


class test_HashGroup(unittest.TestCase):
    def test_serialize(self):
        h1 = ccnpy.HashValue(1, array.array('B', [1, 2]))
        h2 = ccnpy.HashValue(2, array.array('B', [3, 4]))
        h3 = ccnpy.HashValue(3, array.array('B', [5, 6]))
        p = ccnpy.flic.Pointers([h1, h2, h3])
        gd = ccnpy.flic.GroupData(subtree_size=ccnpy.flic.SubtreeSize(0x0234))
        hg = ccnpy.flic.HashGroup(group_data=gd, pointers=p)
        actual = hg.serialize()

        expected = array.array("B", [0, 2, 0, 38,
                                     # Group Data
                                     0, 1, 0, 12,
                                     0, 1, 0,  8, 0, 0, 0, 0, 0, 0, 2, 0x34,
                                     # Pointers
                                     0, 2, 0, 18,
                                     0, 1, 0,  2, 1, 2,
                                     0, 2, 0,  2, 3, 4,
                                     0, 3, 0,  2, 5, 6])
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        h1 = ccnpy.HashValue(1, array.array('B', [1, 2]))
        h2 = ccnpy.HashValue(2, array.array('B', [3, 4]))
        h3 = ccnpy.HashValue(3, array.array('B', [5, 6]))
        p = ccnpy.flic.Pointers([h1, h2, h3])
        gd = ccnpy.flic.GroupData(subtree_size=ccnpy.flic.SubtreeSize(0x0234))
        expected = ccnpy.flic.HashGroup(group_data=gd, pointers=p)

        wire_format = array.array("B", [0, 2, 0, 38,
                                        # Group Data
                                        0, 1, 0, 12,
                                        0, 1, 0,  8, 0, 0, 0, 0, 0, 0, 2, 0x34,
                                        # Pointers
                                        0, 2, 0, 18,
                                        0, 1, 0,  2, 1, 2,
                                        0, 2, 0,  2, 3, 4,
                                        0, 3, 0,  2, 5, 6])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.flic.HashGroup.parse(tlv)
        self.assertEqual(expected, actual)
