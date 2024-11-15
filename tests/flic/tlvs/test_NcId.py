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
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class NcIdTest(unittest.TestCase):
    def test_serialize(self):
        ncid = NcId(5)
        expected = array.array("B", [0, TlvNumbers.T_NCID, 0, 1, 5])
        actual = ncid.serialize()
        self.assertEqual(expected, actual)

    def test_serialize_3_bytes(self):
        ncid = NcId(0x123456)
        expected = array.array("B", [0, TlvNumbers.T_NCID, 0, 3, 0x12, 0x34, 0x56])
        actual = ncid.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, TlvNumbers.T_NCID, 0, 1, 5])
        tlv = Tlv.deserialize(wire_format)
        actual = NcId.parse(tlv)
        expected = NcId(5)
        self.assertEqual(expected, actual)

    def test_deserialize_3_bytes(self):
        wire_format = array.array("B", [0, TlvNumbers.T_NCID, 0, 3, 0x12, 0x34, 0x56])
        tlv = Tlv.deserialize(wire_format)
        actual = NcId.parse(tlv)
        expected = NcId(0x123456)
        self.assertEqual(expected, actual)
