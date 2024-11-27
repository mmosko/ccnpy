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
from array import array

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Link import Link
from ccnpy.core.Name import Name
from ccnpy.crypto.AeadKey import AeadGcm
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.flic.RsaOaepCtx.RsaOaepEncryptor import RsaOaepEncryptor
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.Locator import Locator
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.ManifestFactory import ManifestFactory
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.tlvs.NcDef import NcDef
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import PrefixSchema
from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.RsaOaepCtx import RsaOaepCtx
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers
from tests.MockKeys import shared_1024_pub_pem


class ManiestFactoryTest(unittest.TestCase):
    @staticmethod
    def _create_options(**kwargs):
        return ManifestTreeOptions(name='ccnx:/a', schema_type=SchemaType.HASHED, signer=None, **kwargs)

    simple_wire_format = array('B', [
                               0, TlvNumbers.T_NODE, 0, 14,   # Node
                               0, TlvNumbers.T_HASH_GROUP, 0, 10,   # HashGroup
                               0, TlvNumbers.T_PTRS, 0,  6,   # Pointers
                               0, 1, 0,  2, 1, 2]  # HashValue SHA256 + payload
                         )

    def test_unencrypted_nopts_pointers(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        factory = ManifestFactory(self._create_options())
        rv = factory._build(ptr)
        actual = rv.manifest.serialize()
        self.assertEqual(self.simple_wire_format, actual)

    def test_unencrypted_nopts_hashgroup(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        factory = ManifestFactory(self._create_options())
        rv = factory._build(hg)
        actual = rv.manifest.serialize()
        self.assertEqual(self.simple_wire_format, actual)

    def test_unencrypted_nopts_node(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        node = Node(hash_groups=[hg])
        factory = ManifestFactory(self._create_options())
        rv = factory._build(node)
        actual = rv.manifest.serialize()
        self.assertEqual(self.simple_wire_format, actual)

    def test_unencrypted_opts_pointers(self):
        tree_options = self._create_options(add_group_subtree_size=True, add_node_subtree_size=True)
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        factory = ManifestFactory(tree_options=tree_options)
        rv = factory._build(ptr, node_subtree_size=20, group_subtree_size=16)
        actual = rv.manifest.serialize()

        expected = array('B', [
                               0, TlvNumbers.T_NODE, 0, 32,
                               0, TlvNumbers.T_NODE_DATA, 0, 5,
                               0, TlvNumbers.T_SUBTREE_SIZE, 0,  1, 20,
                               0, TlvNumbers.T_HASH_GROUP, 0, 19,
                               0, TlvNumbers.T_GROUP_DATA, 0, 5,
                               0, TlvNumbers.T_SUBTREE_SIZE, 0,  1, 16,
                               0, TlvNumbers.T_PTRS, 0,  6,   # Pointers
                               0, 1, 0,  2, 1, 2]  # HashValue SHA256 + payload
                         )
        self.assertEqual(expected, actual)

    def test_unencrypted_opts_hashgroup(self):
        tree_options = self._create_options(add_group_subtree_size=True, add_node_subtree_size=True)
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        factory = ManifestFactory(tree_options=tree_options)
        rv = factory._build(hg, node_subtree_size=20, group_subtree_size=16)
        actual = rv.manifest.serialize()

        # Note that we did not add a GroupData to the HashGroup, so it is missing even though
        # the options asked to put it in.
        expected = array('B', [
                               0, TlvNumbers.T_NODE, 0, 23,
                               0, TlvNumbers.T_NODE_DATA, 0, 5,
                               0, TlvNumbers.T_SUBTREE_SIZE, 0,  1, 20,
                               0, TlvNumbers.T_HASH_GROUP, 0, 10,
                               0, TlvNumbers.T_PTRS, 0,  6,   # Pointers
                               0, 1, 0,  2, 1, 2]  # HashValue SHA256 + payload
                         )
        self.assertEqual(expected, actual)

    def test_unencrypted_opts_node(self):
        pass

    def test_encrypted_nopts_node(self):
        key = AeadGcm(array("B", 16 * [1]).tobytes())
        encryptor = AeadEncryptor(key, 99)

        hv = HashValue.create_sha256(array("B", [1, 2]))
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        node = Node(hash_groups=[hg])
        tree_options = self._create_options(manifest_encryptor=encryptor)
        factory = ManifestFactory(tree_options)
        rv = factory._build(node)

        self.assertTrue(rv.manifest.is_encrypted())

        decryptor = AeadDecryptor(key, 99)
        actual_manifest = decryptor.decrypt_manifest(rv.manifest)

        self.assertEqual(node, actual_manifest.node())

    def test_nc_defs(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        factory = ManifestFactory(self._create_options())
        nc_def = NcDef(nc_id=NcId(7), schema=PrefixSchema(name=Name.from_uri('ccnx:/a')))
        rv = factory._build(source=ptr, nc_defs=[nc_def])
        actual = rv.manifest.serialize()

        expected = array('B',[
                    # Node
                    0, TlvNumbers.T_NODE, 0, 40,
                        # Node Data
                        0, TlvNumbers.T_NODE_DATA, 0, 22,
                            # NcDef
                            0, TlvNumbers.T_NCDEF, 0, 18,
                                # ncid
                                0, TlvNumbers.T_NCID, 0, 1, 7,
                                # prefix schema
                                0, TlvNumbers.T_PrefixSchema, 0, 9,
                                    # name
                                    0, 0, 0, 5, 0, 1, 0, 1, 97,
                        # hash group
                        0, TlvNumbers.T_HASH_GROUP, 0, 10,
                            # pointers
                            0, TlvNumbers.T_PTRS, 0, 6,
                                # hash value
                                0, 1, 0, 2, 1, 2
                         ])
        self.assertEqual(expected, actual)

    def test_rsa_oaep_encrypted_nopts_node(self):
        key = AeadGcm(array("B", 16 * [1]).tobytes())
        encryptor = RsaOaepEncryptor.create_with_new_content_key(wrapping_key=RsaKey(shared_1024_pub_pem))

        hv = HashValue.create_sha256(array("B", [1, 2]))
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        node = Node(hash_groups=[hg])
        tree_options = self._create_options(manifest_encryptor=encryptor)
        factory = ManifestFactory(tree_options)
        rv = factory._build(node)

        self.assertTrue(rv.manifest.is_encrypted())
        self.assertIsInstance(rv.manifest.security_ctx(), RsaOaepCtx)

        decryptor = RsaOaepDecryptor()
        decryptor = AeadDecryptor(key, 99)
        actual_manifest = decryptor.decrypt_manifest(rv.manifest)

        self.assertEqual(node, actual_manifest.node())

