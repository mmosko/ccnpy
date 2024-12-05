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
from ccnpy.crypto.AeadKey import AeadGcm, AeadCcm
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.flic.RsaOaepCtx.HashAlg import HashAlg
from ccnpy.flic.RsaOaepCtx.RsaOaepImpl import RsaOaepImpl
from ccnpy.flic.RsaOaepCtx.RsaOaepWrapper import RsaOaepWrapper
from ccnpy.flic.RsaOaepCtx.WrappedKey import WrappedKey
from ccnpy.flic.aeadctx.AeadData import AeadData
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.tlvs.AeadMode import AeadMode
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.KeyNumber import KeyNumber
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.NodeData import NodeData
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.RsaOaepCtx import RsaOaepCtx
from ccnpy.flic.tlvs.SecurityCtx import SecurityCtx
from ccnpy.flic.tlvs.AeadCtx import AeadCtx
from ccnpy.flic.aeadctx.AeadImpl import AeadImpl
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers
from tests.MockKeys import aes_key, shared_1024_pub_pem, shared_1024_key_pem


class RsaOaepImplTest(CcnpyTestCase):

    def setUp(self):
        self.nonce = array.array("B", [77, 88])
        self.keynum = 55
        self.aead_data = AeadData(self.keynum, self.nonce, AeadMode.create_aes_gcm_128())

        wk = WrappedKey(array.array("B", [1, 2, 3, 4]))
        keyid = KeyId(HashValue(1, [5, 6, 7]))
        key_link = KeyLink(Link(Name.from_uri('ccnx:/a')))
        hash_alg = HashAlg(HashFunctionType.T_SHA_256)
        self.rsa_oaep_wrapper = RsaOaepWrapper(key_id=keyid, key_link=key_link, hash_alg=hash_alg, wrapped_key=wk)

    def test_rsaoaepimpl_serialize_1(self):
        ctx = RsaOaepCtx(aead_data=self.aead_data)
        actual = ctx.serialize()
        expected = array.array("B", [
            # SecurityCtx
            0, TlvNumbers.T_SECURITY_CTX, 0, 20,
            # PresharedKeyCtx
            0, TlvNumbers.T_RSAOAEP_CTX, 0, 16,
            # Key Number
            0, TlvNumbers.T_KEYNUM, 0, 1, self.keynum,
            # IV
            0, TlvNumbers.T_NONCE, 0, 2, self.nonce[0], self.nonce[1],
            # Mode
            0, TlvNumbers.T_AEADMode, 0, 1, 1
        ])
        self.assertEqual(expected, actual)
        decoded = RsaOaepCtx.parse(Tlv.deserialize(actual))
        self.assertEqual(ctx, decoded)

    def test_rsaoaepimpl_serialize_2(self):
        ctx = RsaOaepCtx(aead_data=self.aead_data, rsa_oaep_wrapper=self.rsa_oaep_wrapper)
        actual = ctx.serialize()
        expected = array.array("B", [
            # SecurityCtx
            0, TlvNumbers.T_SECURITY_CTX, 0, 57,
            # PresharedKeyCtx
            0, TlvNumbers.T_RSAOAEP_CTX, 0, 53,
            # Key Number
            0, TlvNumbers.T_KEYNUM, 0, 1, self.keynum,
            # IV
            0, TlvNumbers.T_NONCE, 0, 2, self.nonce[0], self.nonce[1],
            # Mode
            0, TlvNumbers.T_AEADMode, 0, 1, 1,
            0, TlvNumbers.T_KEYID, 0, 7, 0, 1, 0, 3, 5, 6, 7,
            0, TlvNumbers.T_KEYLINK, 0, 9,
                0, 0, 0, 5, 0, 1, 0, 1, 97,
            0, TlvNumbers.T_HASH_ALG, 0, 1, 1,
            # This is normally a 128+ byte array from the RSA encryption
            0, TlvNumbers.T_WRAPPED_KEY, 0, 4, 1, 2, 3, 4
        ])

        self.assertEqual(expected, actual)
        decoded = RsaOaepCtx.parse(Tlv.deserialize(actual))
        self.assertEqual(ctx, decoded)

    @staticmethod
    def _create_node() -> Node:
        nd = NodeData(subtree_size=SubtreeSize(1000))
        h1 = HashValue(1, array.array('B', [1, 2]))
        h2 = HashValue(2, array.array('B', [3, 4]))
        h3 = HashValue(3, array.array('B', [5, 6]))
        p1 = Pointers([h1, h2])
        p2 = Pointers([h3])
        gd = GroupData(subtree_size=SubtreeSize(0x0234))
        hg1 = HashGroup(group_data=gd, pointers=p1)
        hg2 = HashGroup(pointers=p2)
        return Node(node_data=nd, hash_groups=[hg1, hg2])

    def test_encrypt_decrypt_node_full_context(self):
        kek = RsaKey(shared_1024_pub_pem)
        salt = 0x01020304
        params = AeadParameters(key=AeadGcm(aes_key), key_number=KeyNumber(55), aead_salt=salt)
        wrapped_key = WrappedKey.create(wrapping_key=kek, params=params)
        wrapper = RsaOaepWrapper.create_sha256(key_id=KeyId(kek.keyid()), wrapped_key=wrapped_key)
        oaep_impl = RsaOaepImpl(aead_params=params, wrapper=wrapper)

        node = self._create_node()

        # include_wrapper=True, e.g. like for the root manifest
        security_ctx, encrypted_node, auth_tag = oaep_impl.encrypt(node, include_wrapper=True)

        self.assertIsInstance(security_ctx, RsaOaepCtx)
        self.assertEqual(wrapper, security_ctx.rsa_oaep_wrapper())
        self.assertEqual(KeyNumber(55), security_ctx.aead_data().key_number())

        keystore = InsecureKeystore()
        kdk = RsaKey(shared_1024_key_pem)
        keystore.add_rsa_key('wrap', kdk)
        receiver_impl = RsaOaepImpl.create(keystore=keystore, rsa_oaep_ctx=security_ctx)

        plaintext = receiver_impl.decrypt_node(
            security_ctx=security_ctx,
            encrypted_node=encrypted_node,
            auth_tag=auth_tag)

        self.assertEqual(node, plaintext)

    def test_encrypt_decrypt_node_partial_context(self):
        kek = RsaKey(shared_1024_pub_pem)
        salt = 0x01020304
        key_number = KeyNumber(55)
        aead_key = AeadCcm(aes_key)
        params = AeadParameters(key=aead_key, key_number=key_number, aead_salt=salt)
        wrapped_key = WrappedKey.create(wrapping_key=kek, params=params)
        wrapper = RsaOaepWrapper.create_sha256(key_id=KeyId(kek.keyid()), wrapped_key=wrapped_key)
        oaep_impl = RsaOaepImpl(aead_params=params, wrapper=wrapper)

        node = self._create_node()

        # include_wrapper=True, e.g. like for the root manifest
        security_ctx, encrypted_node, auth_tag = oaep_impl.encrypt(node, include_wrapper=False)

        self.assertIsInstance(security_ctx, RsaOaepCtx)
        self.assertIsNone(security_ctx.rsa_oaep_wrapper())
        self.assertEqual(KeyNumber(55), security_ctx.aead_data().key_number())

        keystore = InsecureKeystore()
        keystore.add_aes_key(params)
        receiver_impl = RsaOaepImpl.create(keystore=keystore, rsa_oaep_ctx=security_ctx)

        plaintext = receiver_impl.decrypt_node(
            security_ctx=security_ctx,
            encrypted_node=encrypted_node,
            auth_tag=auth_tag)

        self.assertEqual(node, plaintext)
