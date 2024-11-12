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

from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.LeafSize import LeafSize
from ccnpy.flic.tlvs.SuffixComponentType import SuffixComponentType


class SuffixComponentTypeTest(unittest.TestCase):
    def test_serialize(self):
        original = SuffixComponentType(0x1234)
        actual = original.serialize()

        expected = array.array("B", [0, 20, 0, 2, 0x12, 0x34])
        self.assertEqual(expected, actual)

        decoded = SuffixComponentType.parse(Tlv.deserialize(expected))
        self.assertEqual(original, decoded)

    def test_illegal_size(self):
        with self.assertRaises(ValueError):
            SuffixComponentType(0x12345)
