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

from ccnpy.core.HashValue import HashValue, HashFunctionType
from ccnpy.core.KeyId import KeyId
from ccnpy.core.KeyLink import KeyLink
from ccnpy.core.Link import Link
from ccnpy.core.Name import Name
from ccnpy.core.Tlv import Tlv
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.flic.RsaOaepCtx.HashAlg import HashAlg
from ccnpy.flic.RsaOaepCtx.RsaOaepWrapper import RsaOaepWrapper
from ccnpy.flic.RsaOaepCtx.WrappedKey import WrappedKey
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers
from tests.MockKeys import shared_512_pub_pem, aes_key, shared_1024_pub_pem, shared_1024_key_pem


class RsaOaepWrapperTest(CcnpyTestCase):

    def setUp(self):
        wk = WrappedKey(array.array("B", [1, 2, 3, 4]))
        keyid = KeyId(HashValue(1, [5, 6, 7]))
        key_link = KeyLink(Link(Name.from_uri('ccnx:/a')))
        hash_alg = HashAlg(HashFunctionType.T_SHA_256)
        self.wrapper = RsaOaepWrapper(key_id=keyid, key_link=key_link, hash_alg=hash_alg, wrapped_key=wk)


    def test_serialize(self):
        wire_format = self.wrapper.serialize()
        expected_wire_format = array.array("B",[
            0, TlvNumbers.T_KEYID, 0, 7,
                0, 1, 0, 3, 5, 6, 7,
            0, TlvNumbers.T_KEYLINK, 0, 9,
                0, 0, 0, 5, 0, 1, 0, 1, 97,
            0, TlvNumbers.T_HASH_ALG, 0, 1,
                1,
            0, TlvNumbers.T_WRAPPED_KEY, 0, 4,
                1, 2, 3, 4
        ])

        self.assertEqual(expected_wire_format, wire_format)

        decoded = RsaOaepWrapper.parse(wire_format)
        self.assertEqual(self.wrapper, decoded)

    def test_parse_with_extra(self):
        wire_format = array.array("B",[
            0, TlvNumbers.T_KEYNUM, 0, 1,
                1,
            0, TlvNumbers.T_KEYID, 0, 7,
                0, 1, 0, 3, 5, 6, 7,
            0, TlvNumbers.T_KEYLINK, 0, 9,
                0, 0, 0, 5, 0, 1, 0, 1, 97,
            0, TlvNumbers.T_HASH_ALG, 0, 1,
                1,
            0, TlvNumbers.T_WRAPPED_KEY, 0, 4,
                1, 2, 3, 4
        ])
        decoded = RsaOaepWrapper.parse(wire_format)
        self.assertEqual(self.wrapper, decoded)

    def test_parse_as_none(self):
        wire_format = array.array("B",[
            0, TlvNumbers.T_KEYNUM, 0, 1,
                1,
        ])
        decoded = RsaOaepWrapper.parse(wire_format)
        self.assertIsNone(decoded)
