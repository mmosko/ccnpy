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
    # # openssl rand 16 | xxd - -include
    # key = array.array('B', [0x18, 0xd9, 0xab, 0x0a, 0x62, 0x8c, 0x54, 0xea,
    #                         0x32, 0x83, 0xcd, 0x80, 0x4a, 0xb1, 0x94, 0xac])

    nonce = array.array("B", [77, 88])
    keynum = 55

    wire_format = array.array("B", [
        # SecurityCtx
        0, TlvNumbers.T_SECURITY_CTX, 0, 20,
        # PresharedKeyCtx
        0, TlvNumbers.T_AEAD_CTX, 0, 16,
        # Key Number
        0, TlvNumbers.T_KEYNUM, 0, 1, keynum,
        # IV
        0, TlvNumbers.T_NONCE, 0, 2, nonce[0], nonce[1],
        # Mode
        0, TlvNumbers.T_AEADMode, 0, 1, 1
    ])

    def test_aeadctx_serialize(self):
        psk_ctx = AeadCtx(AeadData(self.keynum, self.nonce, AeadMode.create_aes_gcm_128()))
        actual = psk_ctx.serialize()
        self.assertEqual(self.wire_format, actual)

    def test_aeadctx_deserialize(self):
        tlv = Tlv.deserialize(self.wire_format)
        psk_ctx = SecurityCtx.parse(tlv)
        expected = AeadCtx(AeadData(self.keynum, array.array("B", self.nonce), AeadMode.create_aes_gcm_128()))
        self.assertEqual(expected, psk_ctx)

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

    def test_encrypt_decrypt_node(self):
        key = AeadGcm(aes_key)
        psk = AeadImpl(AeadParameters(key=key, key_number=55))

        node = self._create_node()
        security_ctx, encrypted_node, auth_tag = psk.encrypt(node)

        plaintext = psk.decrypt_node(security_ctx=security_ctx,
                                     encrypted_node=encrypted_node,
                                     auth_tag=auth_tag)

        self.assertEqual(node, plaintext)

    def test_encrypt_decrypt_node_with_salt(self):
        key = AeadGcm(aes_key)
        # the salt should be paded out to 4 bytes
        psk = AeadImpl(AeadParameters(key=key, key_number=55, aead_salt=0x010203))

        node = self._create_node()
        security_ctx, encrypted_node, auth_tag = psk.encrypt(node)

        plaintext = psk.decrypt_node(security_ctx=security_ctx,
                                     encrypted_node=encrypted_node,
                                     auth_tag=auth_tag)

        self.assertEqual(node, plaintext)

    def test_encrypt_decrypt_manifest(self):
        node = self._create_node()
        key = AeadCcm(aes_key)
        psk = AeadImpl(AeadParameters(key=key, key_number=55))
        encrypted_manifest = psk.create_encrypted_manifest(node)
        decrypted_manifest = psk.decrypt_manifest(encrypted_manifest)
        expected = Manifest(node=node)
        self.assertEqual(expected, decrypted_manifest)

    def test_encrypt_decrypt_node_with_kdf(self):
        key = AeadGcm(aes_key)
        info = b'a publisher id'
        kdf_data = KdfData.create_hkdf_sha256(KdfInfo(info))
        psk = AeadImpl(AeadParameters(key=key, key_number=55, aead_salt=0x010203, kdf_data=kdf_data, kdf_salt=0x030609))

        node = self._create_node()
        security_ctx, encrypted_node, auth_tag = psk.encrypt(node)

        plaintext = psk.decrypt_node(security_ctx=security_ctx,
                                     encrypted_node=encrypted_node,
                                     auth_tag=auth_tag)
        self.assertEqual(node, plaintext)