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

from ccnpy.core.PayloadType import PayloadType
from ccnpy.core.Tlv import Tlv


class PayloadTypeTest(CcnpyTestCase):
    def test_serialize(self):
        pt = PayloadType.create_link_type()
        self.assertTrue(pt.is_link(), "did not test as Link type")
        expected = array.array("B", [0, 5, 0, 1, 2])
        actual = pt.serialize()
        self.assertEqual(expected, actual, "Incorrect serialization")

    def test_deserialize(self):
        wire_format = array.array("B", [0, 5, 0, 1, 2])
        tlv = Tlv.deserialize(wire_format)
        expected = PayloadType.create_link_type()
        actual = PayloadType.parse(tlv)
        self.assertEqual(expected, actual, "Incorrect deserialize")
