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
from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.Vendor import Vendor


class VendorTest(CcnpyTestCase):
    def test_serialize_no_payload(self):
        v = Vendor(0x1234, [])
        actual = v.serialize()

        expected = array.array("B", [0x0F, 0xFF, 0, 3, 0, 0x12, 0x34])
        self.assertEqual(expected, actual)

    def test_serialize_payload(self):
        v = Vendor(0x1234, [5, 6, 7, 8])
        actual = v.serialize()

        expected = array.array("B", [0x0F, 0xFF, 0, 7, 0, 0x12, 0x34, 5, 6, 7, 8])
        self.assertEqual(expected, actual)

    def test_deserialize_no_payload(self):
        wire_format = array.array("B", [0x0F, 0xFF, 0, 3, 0, 0x12, 0x34])
        tlv = Tlv.deserialize(wire_format)
        actual = Vendor.parse(tlv)
        expected = Vendor(0x1234, [])
        self.assertEqual(expected, actual)

    def test_deserialize_payload(self):
        wire_format = array.array("B", [0x0F, 0xFF, 0, 7, 0, 0x12, 0x34, 5, 6, 7, 8])
        tlv = Tlv.deserialize(wire_format)
        actual = Vendor.parse(tlv)
        expected = Vendor(0x1234, [5, 6, 7, 8])
        self.assertEqual(expected, actual)
