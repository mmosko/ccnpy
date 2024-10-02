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


import unittest

import ccnpy.crypto


class Crc32c_Signer_Test(unittest.TestCase):
    def test_signer(self):
        # checksum is in little-endian byte order of the Reversed generator (0x82F63B78)
        vectors = [(b'the quick brown fox', 0x3355EFD3),
                   (b'The quick brown fox jumps over the lazy dog', 0x22620404),
                   (b'abcdefg', 0xE627F441)]

        signer = ccnpy.crypto.Crc32c_Signer()
        for (buffer, checksum) in vectors:
            actual = signer.sign(buffer)
            expected = ccnpy.ValidationPayload(ccnpy.Tlv.uint32_to_array(checksum))
            self.assertEqual(expected, actual, buffer)

    def test_verify(self):
        vectors = [(b'the quick brown fox', 0x3355EFD3, True),
                   (b'The quick brown fox jumps over the lazy dog', 0x22620404, True),
                   (b'abcdefg', 0xE627F441, True),
                   (b'abcdefg', 0xE627F400, False)]

        verifier = ccnpy.crypto.Crc32c_Verifier()
        for (buffer, checksum, expected) in vectors:
            validation_payload = ccnpy.ValidationPayload(ccnpy.Tlv.uint32_to_array(checksum))
            actual = verifier.verify(buffer, validation_payload=validation_payload)
            self.assertEqual(expected, actual, buffer)

    def test_two_buffers(self):
        b1 = b'The quick brown fox '
        b2 = b'jumps over the lazy dog'
        truth = 0x22620404

        signer = ccnpy.crypto.Crc32c_Signer()
        actual = signer.sign(b1, b2)
        expected = ccnpy.ValidationPayload(ccnpy.Tlv.uint32_to_array(truth))
        self.assertEqual(expected, actual, "two buffers failed")

        verifier = ccnpy.crypto.Crc32c_Verifier()
        result = verifier.verify(b1, b2, validation_payload=expected)
        self.assertTrue(result)