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

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Tlv import Tlv
from ccnpy.crypto.AeadKey import AeadGcm, AeadCcm
from ccnpy.flic.aeadctx.AeadData import AeadData
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.tlvs.AeadMode import AeadMode
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.KdfData import KdfData
from ccnpy.flic.tlvs.KdfInfo import KdfInfo
from ccnpy.flic.tlvs.KeyNumber import KeyNumber
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.NodeData import NodeData
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.SecurityCtx import SecurityCtx
from ccnpy.flic.tlvs.AeadCtx import AeadCtx
from ccnpy.flic.aeadctx.AeadImpl import AeadImpl
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers
from tests.MockKeys import aes_key


class AeadImplTest(CcnpyTestCase):
    def setUp(self):
        self.key = AeadGcm.generate(128)

    def test_no_optional(self):
        p = AeadParameters(
            key=self.key,
            key_number=7
        )

        self.assertEqual(self.key, p.key)
        self.assertEqual(KeyNumber(7), p.key_number)
        self.assertIsNone(p.aead_salt)
        self.assertIsNone(p.aead_salt_bytes)
        self.assertIsNone(p.kdf_data)
        self.assertIsNone(p.kdf_salt)
        self.assertIsNone(p.kdf_salt_bytes)

    def test_with_optional(self):
        kdf_data = KdfData.create_hkdf_sha256(KdfInfo(b'\x07\x08'))
        p = AeadParameters(
            key=self.key,
            key_number=7,
            aead_salt=0x010203,
            kdf_data=kdf_data,
            kdf_salt=0x0a0b
        )

        self.assertEqual(self.key, p.key)
        self.assertEqual(KeyNumber(7), p.key_number)
        self.assertEqual(0x010203, p.aead_salt)
        self.assertEqual(b'\x00\x01\x02\x03', p.aead_salt_bytes)
        self.assertEqual(kdf_data, p.kdf_data)
        self.assertEqual(0x0a0b, p.kdf_salt)
        self.assertEqual(b'\x00\x00\x0a\x0b', p.kdf_salt_bytes)

