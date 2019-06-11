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


class PayloadType_Test(unittest.TestCase):
    def test_serialize(self):
        pt = ccnpy.PayloadType.create_link_type()
        self.assertTrue(pt.is_link(), "did not test as Link type")
        expected = array.array("B", [0, 5, 0, 1, 2])
        actual = pt.serialize()
        self.assertEqual(expected, actual, "Incorrect serialization")

    def test_deserialize(self):
        wire_format = array.array("B", [0, 5, 0, 1, 2])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        expected = ccnpy.PayloadType.create_link_type()
        actual = ccnpy.PayloadType.deserialize(tlv)
        self.assertEqual(expected, actual, "Incorrect deserialize")
