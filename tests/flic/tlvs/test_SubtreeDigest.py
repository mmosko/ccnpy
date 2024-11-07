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

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.SubtreeDigest import SubtreeDigest


class SubtreeDigestTest(unittest.TestCase):
    def test_serialize(self):
        hv = HashValue(55, array.array("B", [1, 2, 3]))
        sd = SubtreeDigest(hv)
        actual = sd.serialize()

        expected = array.array("B", [0, 2, 0, 7, 0, 55, 0, 3, 1, 2, 3])
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, 2, 0, 7, 0, 55, 0, 3, 1, 2, 3])
        tlv = Tlv.deserialize(wire_format)
        sd = SubtreeDigest.parse(tlv)
        expected = SubtreeDigest(HashValue(55, array.array("B", [1, 2, 3])))
        self.assertEqual(expected, sd)
