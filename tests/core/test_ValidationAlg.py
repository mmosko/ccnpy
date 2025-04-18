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
from ccnpy.core.SignatureTime import SignatureTime
from ccnpy.core.Tlv import Tlv
from ccnpy.core.ValidationAlg import ValidationAlg_Crc32c, ValidationAlg, ValidationAlg_RsaSha256


class ValidationAlgTest(CcnpyTestCase):
    def test_crc32c_serialize(self):
        va = ValidationAlg_Crc32c()
        actual = va.serialize()
        expected = array.array("B", [0, 3, 0, 4, 0, 2, 0, 0])
        self.assertEqual(expected, actual, "Incorrect serialization")

    def test_crc32c_deserialize(self):
        wire_format = array.array("B", [0, 3, 0, 4, 0, 2, 0, 0])
        tlv = Tlv.deserialize(wire_format)
        expected = ValidationAlg_Crc32c()
        actual = ValidationAlg.parse(tlv)
        self.assertEqual(expected, actual)

    def test_rsasha256_serialize_keyid(self):
        keyid = HashValue.create_sha256(b'abc')
        sigtime = SignatureTime.parse(Tlv(SignatureTime.class_type(), array.array("B", [0, 0, 2, 3, 4, 5, 6, 7])))
        va = ValidationAlg_RsaSha256(keyid=keyid, signature_time=sigtime)
        actual = va.serialize()
        expected = array.array("B", [0,  3, 0, 27,
                                     0,  4, 0, 23,
                                     0,  9, 0,  7, 0, 1, 0, 3, 97, 98, 99,
                                     0, 15, 0,  8, 0, 0, 2, 3, 4, 5, 6, 7])
        self.assertEqual(expected, actual, "Incorrect serialization")

    def test_rsasha256_deserialize_keyid(self):
        keyid = HashValue.create_sha256(b'abc')
        sigtime = SignatureTime.parse(Tlv(SignatureTime.class_type(), array.array("B", [0, 0, 2, 3, 4, 5, 6, 7])))
        expected = ValidationAlg_RsaSha256(keyid=keyid, signature_time=sigtime)

        wire_format = array.array("B", [0,  3, 0, 27,
                                        0,  4, 0, 23,
                                        0,  9, 0,  7, 0, 1, 0, 3, 97, 98, 99,
                                        0, 15, 0,  8, 0, 0, 2, 3, 4, 5, 6, 7])
        tlv = Tlv.deserialize(wire_format)
        actual = ValidationAlg.parse(tlv)
        self.assertEqual(expected, actual)
