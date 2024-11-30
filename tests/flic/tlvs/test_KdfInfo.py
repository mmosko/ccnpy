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
from ccnpy.flic.tlvs.KdfInfo import KdfInfo
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class KdfInfoTest(CcnpyTestCase):
    def test_serialize(self):
        info = KdfInfo(b'abcd')
        expected = array.array("B", [
            0, TlvNumbers.T_KDF_INFO, 0, 4, 97, 98, 99, 100])
        actual = info.serialize()
        self.assertEqual(expected, actual)

        decoded = KdfInfo.parse(Tlv.deserialize(actual))
        self.assertEqual(info, decoded)
