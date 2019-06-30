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

import array
import unittest

import ccnpy
import ccnpy.flic


class test_Pointers(unittest.TestCase):
    def test_serialize(self):
        h1 = ccnpy.HashValue(1, array.array('B', [1, 2]))
        h2 = ccnpy.HashValue(2, array.array('B', [3, 4]))
        h3 = ccnpy.HashValue(3, array.array('B', [5, 6]))

        p = ccnpy.flic.Pointers([h1, h2, h3])
        actual = p.serialize()

        expected = array.array("B", [0, 2, 0, 18,
                                     0, 1, 0,  2, 1, 2,
                                     0, 2, 0,  2, 3, 4,
                                     0, 3, 0,  2, 5, 6])
        self.assertEqual(expected, actual)

    def test_parse(self):
        h1 = ccnpy.HashValue(1, array.array('B', [1, 2]))
        h2 = ccnpy.HashValue(2, array.array('B', [3, 4]))
        h3 = ccnpy.HashValue(3, array.array('B', [5, 6]))
        expected = ccnpy.flic.Pointers([h1, h2, h3])

        wire_format = array.array("B", [0, 2, 0, 18,
                                        0, 1, 0,  2, 1, 2,
                                        0, 2, 0,  2, 3, 4,
                                        0, 3, 0,  2, 5, 6])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.flic.Pointers.parse(tlv)
        self.assertEqual(expected, actual)
