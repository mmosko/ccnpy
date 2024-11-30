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
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.flic.tlvs.ProtocolFlags import ProtocolFlags
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class ProtocolFlagsTest(CcnpyTestCase):
    def test_serialize(self):
        flags = array.array("B", [1, 3, 5, 7, 9])
        pf = ProtocolFlags(flags)
        expected = array.array("B", [0, TlvNumbers.T_PROTOCOL_FLAGS, 0, 5, 1, 3, 5, 7, 9])
        actual = pf.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, TlvNumbers.T_PROTOCOL_FLAGS, 0, 5, 1, 3, 5, 7, 9])
        tlv = Tlv.deserialize(wire_format)
        actual = ProtocolFlags.parse(tlv)
        expected = ProtocolFlags([1, 3, 5, 7, 9])
        self.assertEqual(expected, actual)

    def test_deserialize_wrong_tlv(self):
        wire_format = array.array("B", [0, 99, 0, 5, 1, 3, 5, 7, 9])
        tlv = Tlv.deserialize(wire_format)
        with self.assertRaises(CannotParseError):
            ProtocolFlags.parse(tlv)
