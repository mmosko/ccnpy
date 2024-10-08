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

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Tlv import Tlv
from ccnpy.crypto.AeadKey import AeadGcm, AeadCcm
from ccnpy.flic.GroupData import GroupData
from ccnpy.flic.HashGroup import HashGroup
from ccnpy.flic.Manifest import Manifest
from ccnpy.flic.Node import Node
from ccnpy.flic.NodeData import NodeData
from ccnpy.flic.Pointers import Pointers
from ccnpy.flic.SecurityCtx import SecurityCtx
from ccnpy.flic.annotations.SubtreeSize import SubtreeSize
from ccnpy.flic.aeadctx.AeadImpl import AeadImpl
from ccnpy.flic.aeadctx.AeadCtx import AeadCtx


class AeadImplTest(unittest.TestCase):
    key = array.array('B', [0x18, 0xd9, 0xab, 0x0a, 0x62, 0x8c, 0x54, 0xea,
                            0x32, 0x83, 0xcd, 0x80, 0x4a, 0xb1, 0x94, 0xac])

    def test_aeadctx_serialize(self):
        psk_ctx = AeadCtx.create_aes_gcm_128(55, array.array("B", [77, 88]))
        actual = psk_ctx.serialize()

        expected = array.array("B", [ # SecurityCtx
                                      0, 1, 0, 20,
                                      # PresharedKeyCtx
                                      0, 1, 0, 16,
                                      # Key Number
                                      0, 1, 0, 1, 55,
                                      # IV
                                      0, 2, 0, 2, 77, 88,
                                      # Mode
                                      0, 3, 0, 1, 1
                                     ])
        self.assertEqual(expected, actual)

    def test_aeadctx_deserialize(self):
        wire_format = array.array("B", [0, 1, 0, 20,
                                        0, 1, 0, 16,
                                        0, 1, 0, 1, 55,
                                        0, 2, 0, 2, 77, 88,
                                        0, 3, 0, 1, 1
                                        ])
        tlv = Tlv.deserialize(wire_format)
        psk_ctx = SecurityCtx.parse(tlv)
        expected = AeadCtx.create_aes_gcm_128(55, array.array("B", [77, 88]))
        self.assertEqual(expected, psk_ctx)

    def test_encrypt_decrypt_node(self):
        nd = NodeData(subtree_size=SubtreeSize(1000))

        h1 = HashValue(1, array.array('B', [1, 2]))
        h2 = HashValue(2, array.array('B', [3, 4]))
        h3 = HashValue(3, array.array('B', [5, 6]))
        p1 = Pointers([h1, h2])
        p2 = Pointers([h3])
        gd = GroupData(subtree_size=SubtreeSize(0x0234))

        hg1 = HashGroup(group_data=gd, pointers=p1)
        hg2 = HashGroup(pointers=p2)

        node = Node(node_data=nd, hash_groups=[hg1, hg2])

        aes_key = AeadGcm(self.key)
        psk = AeadImpl(key=aes_key, key_number=55)
        security_ctx, encrypted_node, auth_tag = psk.encrypt(node)

        plaintext = psk.decrypt_node(security_ctx=security_ctx,
                                     encrypted_node=encrypted_node,
                                     auth_tag=auth_tag)

        self.assertEqual(node, plaintext)

    def test_encrypt_decrypt_manifest(self):
        nd = NodeData(subtree_size=SubtreeSize(1000))

        h1 = HashValue(1, array.array('B', [1, 2]))
        h2 = HashValue(2, array.array('B', [3, 4]))
        h3 = HashValue(3, array.array('B', [5, 6]))
        p1 = Pointers([h1, h2])
        p2 = Pointers([h3])
        gd = GroupData(subtree_size=SubtreeSize(0x0234))

        hg1 = HashGroup(group_data=gd, pointers=p1)
        hg2 = HashGroup(pointers=p2)

        node = Node(node_data=nd, hash_groups=[hg1, hg2])

        aes_key = AeadCcm(self.key)
        psk = AeadImpl(key=aes_key, key_number=55)
        encrypted_manifest = psk.create_encrypted_manifest(node)

        decrypted_manifest = psk.decrypt_manifest(encrypted_manifest)
        expected = Manifest(node=node)

        self.assertEqual(expected, decrypted_manifest)
