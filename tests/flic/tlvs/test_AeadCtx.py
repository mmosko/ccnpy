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
from ccnpy.flic.aeadctx.AeadData import AeadData
from ccnpy.flic.tlvs.AeadCtx import AeadCtx
from ccnpy.flic.tlvs.AeadMode import AeadMode
from ccnpy.flic.tlvs.KdfData import KdfData
from ccnpy.flic.tlvs.KdfInfo import KdfInfo
from ccnpy.flic.tlvs.KeyNumber import KeyNumber
from ccnpy.flic.tlvs.Nonce import Nonce
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class AeadCtxTest(unittest.TestCase):

    def test_serialize(self):
        psk_ctx = AeadCtx(AeadData(key_number=KeyNumber(12), nonce=Nonce([1, 2]), mode=AeadMode.create_aes_gcm_128()))
        actual = psk_ctx.serialize()
        wire_format = array.array("B", [
            # SecurityCtx wrapper
            0, TlvNumbers.T_SECURITY_CTX, 0, 20,
            # AeadCtx
            0, TlvNumbers.T_AEAD_CTX, 0, 16,
            # Key Number
            0, TlvNumbers.T_KEYNUM, 0, 1, 12,
            # IV
            0, TlvNumbers.T_NONCE, 0, 2, 1, 2,
            # Mode
            0, TlvNumbers.T_AEADMode, 0, 1, 1
        ])
        self.assertEqual(wire_format, actual)
        decoded = AeadCtx.parse(Tlv.deserialize(wire_format))
        self.assertEqual(psk_ctx, decoded)

    def test_getters(self):
        psk_ctx = AeadCtx(AeadData(key_number=KeyNumber(12), nonce=Nonce([1, 2]), mode=AeadMode.create_aes_gcm_128()))
        self.assertEqual(KeyNumber(12), psk_ctx.key_number())
        self.assertEqual(Nonce([1,2]), psk_ctx.nonce())
        self.assertTrue(psk_ctx.aead_data().mode().is_aes_gcm_128())

    def test_serialize_with_kdf(self):
        kdf_info = KdfInfo(value=[32, 33, 34])
        kdf_data = KdfData.create_hkdf_sha256(kdf_info)
        psk_ctx = AeadCtx(AeadData(key_number=KeyNumber(12),
                                   nonce=Nonce([1, 2]),
                                   mode=AeadMode.create_aes_gcm_128(),
                                   kdf_data=kdf_data))
        actual = psk_ctx.serialize()
        wire_format = array.array("B", [
            # SecurityCtx wrapper
            0, TlvNumbers.T_SECURITY_CTX, 0, 36,
            # AeadCtx
            0, TlvNumbers.T_AEAD_CTX, 0, 32,
            # Key Number
            0, TlvNumbers.T_KEYNUM, 0, 1, 12,
            # IV
            0, TlvNumbers.T_NONCE, 0, 2, 1, 2,
            # Mode
            0, TlvNumbers.T_AEADMode, 0, 1, 1,
            # KDF
            0, TlvNumbers.T_KDF_DATA, 0, 12,
            0, TlvNumbers.T_KDF_ALG, 0, 1, 1,
            0, TlvNumbers.T_KDF_INFO, 0, 3, 32, 33, 34
        ])
        self.assertEqual(wire_format, actual)
        decoded = AeadCtx.parse(Tlv.deserialize(wire_format))
        self.assertEqual(psk_ctx, decoded)
