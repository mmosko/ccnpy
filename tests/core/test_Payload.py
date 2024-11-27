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

from ccnpy.core.Payload import Payload
from ccnpy.core.Tlv import Tlv


class PayloadTest(unittest.TestCase):
    def test_serialize(self):
        payload = Payload(array.array("B", [1, 2, 3, 4]))
        expected = array.array("B", [0, Payload.class_type(), 0, 4, 1, 2, 3, 4])
        actual = payload.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, Payload.class_type(), 0, 4, 1, 2, 3, 4])
        tlv = Tlv.deserialize(wire_format)
        actual = Payload.parse(tlv)
        expected = Payload(array.array("B", [1, 2, 3, 4]))
        self.assertEqual(expected, actual)

    def test_list_input(self):
        payload = Payload([1, 2, 3])
        expected = array.array("B", [1, 2, 3])
        self.assertEqual(expected, payload.value())

    def test_bytes_input(self):
        payload = Payload(b"\01\02\03")
        expected = array.array("B", [1, 2, 3])
        self.assertEqual(expected, payload.value())

    def test_value_bytes(self):
        input = b"\01\02\03"
        payload = Payload(input)
        self.assertEqual(input, payload.value_bytes())