# Copyright 2019 Marc Mosko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
import array
import ccnpy


class ValidationPayload_Test(unittest.TestCase):

    def test_serialize(self):
        payload = array.array("B", [1, 2, 3, 4, 5, 6])
        vp = ccnpy.ValidationPayload(payload)
        expected = array.array("B", [0, 4, 0, 6, 1, 2, 3, 4, 5, 6])
        actual = vp.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        payload = array.array("B", [1, 2, 3, 4, 5, 6])
        tlv = ccnpy.Tlv(ccnpy.TlvType.T_VALIDATION_PAYLOAD, payload)
        expected = ccnpy.ValidationPayload(payload)
        actual = ccnpy.ValidationPayload.deserialize(tlv)
        self.assertEqual(expected, actual)