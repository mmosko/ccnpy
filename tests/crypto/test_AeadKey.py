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

from ccnpy.crypto.AeadKey import AeadGcm, AeadCcm
from tests.MockKeys import aes_key


class AeadKeyTest(unittest.TestCase):
    def _aead(self, key, nonce_length):
        buffer = array.array("B", b'somewhere over the rainbow')
        aad = array.array("B", b'way up high')

        key = AeadGcm(aes_key)
        iv = key.nonce()
        self.assertEqual(nonce_length, len(iv))
        (c, a) = key.encrypt(iv=iv, plaintext=buffer, associated_data=aad)
        plaintext = key.decrypt(iv=iv, ciphertext=c, associated_data=aad, auth_tag=a)
        self.assertEqual(buffer, plaintext)

    def test_gcm_encrypt_decrypt(self):
        key = AeadGcm(aes_key)
        self._aead(key, 12)

    def test_ccm_encrypt_decrypt(self):
        key = AeadCcm(aes_key)
        self._aead(key, 12)
