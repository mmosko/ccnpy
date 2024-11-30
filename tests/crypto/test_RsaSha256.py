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


from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256Signer, RsaSha256Verifier
from tests.MockKeys import private_key_pem, public_key_pem


class RsaSha256SignerTest(CcnpyTestCase):
    # openssl genrsa -out test_key.pem

    def test_sign_verify(self):
        # checksum is in little-endian byte order of the Reversed generator (0x82F63B78)
        vectors = [b'the quick brown fox',
                   b'The quick brown fox jumps over the lazy dog',
                   b'abcdefg']

        private_key = RsaKey(private_key_pem)
        public_key = RsaKey(public_key_pem)

        signer = RsaSha256Signer(private_key)
        verifier = RsaSha256Verifier(public_key)

        for buffer in vectors:
            signature = signer.sign(buffer)
            result = verifier.verify(buffer, validation_payload=signature)
            self.assertTrue(result, buffer)
