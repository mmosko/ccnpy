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


class test_AuthTag(unittest.TestCase):
    def test_serialize(self):
        tag = ccnpy.flic.AuthTag(array.array("B", [1, 2, 3, 4]))
        expected = array.array("B", [0, 3, 0, 4, 1, 2, 3, 4])
        actual = tag.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, 3, 0, 4, 1, 2, 3, 4])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.flic.AuthTag.parse(tlv)
        expected = ccnpy.flic.AuthTag(array.array("B", [1, 2, 3, 4]))
        self.assertEqual(expected, actual)