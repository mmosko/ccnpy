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

from ccnpy.core.FinalChunkId import FinalChunkId
from ccnpy.core.Tlv import Tlv


class FinalChunkIdTest(CcnpyTestCase):
    def test_serialize(self):
        fcid = FinalChunkId(0x123456)
        expected = array.array("B", [0, FinalChunkId.class_type(), 0, 3, 0x12, 0x34, 0x56])
        actual = fcid.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, FinalChunkId.class_type(), 0, 3, 0x12, 0x34, 0x56])
        tlv = Tlv.deserialize(wire_format)
        actual = FinalChunkId.parse(tlv)
        expected = FinalChunkId(0x123456)
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(FinalChunkIdTest())

