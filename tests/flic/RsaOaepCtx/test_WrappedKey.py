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

from ccnpy.crypto.AeadKey import AeadGcm
from ccnpy.flic.aeadctx.AeadData import AeadData
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.tlvs.AeadMode import AeadMode
from ccnpy.flic.tlvs.Nonce import Nonce
from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.core.Tlv import Tlv
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.flic.RsaOaepCtx.WrappedKey import WrappedKey
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers
from tests.MockKeys import shared_512_pub_pem, aes_key, shared_1024_pub_pem, shared_1024_key_pem


class WrappedKeyTest(CcnpyTestCase):

    def test_payload(self):
        buffer = array.array("B", [1, 2, 3, 4])
        wk = WrappedKey(buffer)
        self.assertEqual(buffer, wk.value())
        wire_format = wk.serialize()
        self.assertEqual(array.array("B", [0, TlvNumbers.T_WRAPPED_KEY, 0, 4, 1, 2, 3, 4]), wire_format)
        actual = WrappedKey.parse(Tlv.deserialize(wire_format))
        self.assertEqual(wk, actual)

    def test_encrypted_bad_key(self):
        # key is too small for RSA-OAEP
        pub_key = RsaKey(shared_512_pub_pem)
        params = AeadParameters(key=AeadGcm(aes_key), key_number=3, aead_salt=0)
        with self.assertRaises(ValueError):
            WrappedKey.create(wrapping_key=pub_key, params=params)

    def test_encrypted(self):
        pub_key = RsaKey(shared_1024_pub_pem)
        salt = 0x11223344
        params = AeadParameters(key=AeadGcm(aes_key), key_number=3, aead_salt=salt)
        wk = WrappedKey.create(wrapping_key=pub_key, params=params)
        # OAEP makes the wire format unpredictable, so cannot directly test.
        priv_key = RsaKey(shared_1024_key_pem)
        actual_salt, actual_key = wk.decrypt(
            wrapping_key=priv_key,
            aead_data=AeadData(key_number=3, mode=AeadMode.create_aes_gcm_128(), nonce=Nonce([0])))
        self.assertEqual(salt, actual_salt)
        self.assertEqual(aes_key, actual_key)
        # encryption will be size of rsa key
        self.assertEqual(128, len(wk.value()))
