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
from ccnpy.flic.tlvs.LeafSize import LeafSize
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class LeafSizeTest(CcnpyTestCase):
    def test_serialize(self):
        ss = LeafSize(0x010203)
        actual = ss.serialize()

        expected = array.array("B", [0, TlvNumbers.T_LEAF_SIZE, 0, 3, 1, 2, 3])
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, TlvNumbers.T_LEAF_SIZE, 0, 3, 1, 2, 3])
        tlv = Tlv.deserialize(wire_format)
        actual = LeafSize.parse(tlv)
        expected = LeafSize(0x010203)
        self.assertEqual(expected, actual)
