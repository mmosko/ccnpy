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


class AeadKeyTest(unittest.TestCase):
    # openssl rand 16 | xxd - -include
    key = array.array('B', [0x18, 0xd9, 0xab, 0x0a, 0x62, 0x8c, 0x54, 0xea,
                            0x32, 0x83, 0xcd, 0x80, 0x4a, 0xb1, 0x94, 0xac])

    def test_gcm_encrypt_decrypt(self):
        buffer = array.array("B", b'somewhere over the rainbow')
        aad = array.array("B", b'way up high')

        key = AeadGcm(self.key)
        iv = key.nonce()
        (c, a) = key.encrypt(iv=iv, plaintext=buffer, associated_data=aad)
        # print("nonce      = %r" % iv)
        # print("ciphertext = %r" % c)
        # print("authtag    = %r" % a)
        plaintext = key.decrypt(iv=iv, ciphertext=c, associated_data=aad, auth_tag=a)
        self.assertEqual(buffer, plaintext)

    def test_ccm_encrypt_decrypt(self):
        buffer = array.array("B", b'somewhere over the rainbow')
        aad = array.array("B", b'way up high')

        key = AeadCcm(self.key)
        iv = key.nonce()
        (c, a) = key.encrypt(iv=iv, plaintext=buffer, associated_data=aad)
        # print("nonce      = %r" % iv)
        # print("ciphertext = %r" % c)
        # print("authtag    = %r" % a)
        plaintext = key.decrypt(iv=iv, ciphertext=c, associated_data=aad, auth_tag=a)
        self.assertEqual(buffer, plaintext)
