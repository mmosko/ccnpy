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


class ExpiryTime_Test(unittest.TestCase):
    def test_serialize(self):
        timestamp = 1560227545.906023
        expiry = ccnpy.ExpiryTime(timestamp)
        actual = expiry.serialize()
        expected = array.array("B", [0, 6, 0, 8, 0x00, 0x00, 0x01, 0x6b, 0x44, 0xcf, 0x03, 0x32])
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, 6, 0, 8, 0x00, 0x00, 0x01, 0x6b, 0x44, 0xcf, 0x03, 0x32])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.ExpiryTime.parse(tlv)

        timestamp = 1560227545.906
        expected = ccnpy.ExpiryTime(timestamp)
        self.assertEqual(expected, actual)
