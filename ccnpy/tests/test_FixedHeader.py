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


class FixedHeader_Test(unittest.TestCase):
    def test_serialize(self):
        fh = ccnpy.FixedHeader(ver=1, packet_type=1, packet_length=0x0102, fields=[7, 8, 9], header_length=8)
        actual = fh.serialize()
        truth = array.array("B", [1, 1, 1, 2, 7, 8, 9, 8])
        self.assertEqual(actual, truth, "incorrect fixed header")

    def test_deserialize(self):
        wire_format = array.array("B", [1, 1, 1, 2, 7, 8, 9, 8])
        truth = ccnpy.FixedHeader(ver=1, packet_type=1, packet_length=0x0102, fields=[7, 8, 9], header_length=8)
        actual = ccnpy.FixedHeader.deserialize(wire_format)
        self.assertEqual(actual, truth, "incorrect fixed header")


