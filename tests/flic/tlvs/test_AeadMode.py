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
from ccnpy.flic.tlvs.AeadMode import AeadMode
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class AeadModeTest(CcnpyTestCase):

    def test_serialize(self):
        mode = AeadMode.create_aes_gcm_128()
        wire_format = mode.serialize()
        expected = array.array("B", [0, TlvNumbers.T_AEADMode, 0, 1, 1])
        self.assertEqual(expected, wire_format)
        decoded = AeadMode.parse(Tlv.deserialize(wire_format))
        self.assertEqual(mode, decoded)

    def test_mode_gcm_128(self):
        mode = AeadMode.create_aes_gcm_128()
        self.assertTrue(mode.is_aes_gcm_128())

    def test_mode_gcm_256(self):
        mode = AeadMode.create_aes_gcm_256()
        self.assertTrue(mode.is_aes_gcm_256())

    def test_mode_ccm_128(self):
        mode = AeadMode.create_aes_ccm_128()
        self.assertTrue(mode.is_aes_ccm_128())

    def test_mode_ccm_256(self):
        mode = AeadMode.create_aes_ccm_256()
        self.assertTrue(mode.is_aes_ccm_256())
