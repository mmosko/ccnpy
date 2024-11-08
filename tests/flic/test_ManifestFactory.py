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


class ManiestFactoryTest(unittest.TestCase):
    @staticmethod
    def _create_options(**kwargs):
        return ManifestTreeOptions(name='ccnx:/a', schema_type=SchemaType.HASHED, signer=None, **kwargs)

    def test_unencrypted_nopts_pointers(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        factory = ManifestFactory(self._create_options())
        manifest = factory.build(ptr)
        actual = manifest.serialize()

        expected = array('B', [0, 2, 0, 14,   # Node
                               0, 2, 0, 10,   # HashGroup
                               0, 2, 0,  6,   # Pointers
                               0, 1, 0,  2, 1, 2]  # HashValue SHA256 + payload
                         )
        self.assertEqual(expected, actual)

    def test_unencrypted_nopts_hashgroup(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        factory = ManifestFactory(self._create_options())
        manifest = factory.build(hg)
        actual = manifest.serialize()

        expected = array('B', [0, 2, 0, 14,   # Node
                               0, 2, 0, 10,   # HashGroup
                               0, 2, 0,  6,   # Pointers
                               0, 1, 0,  2, 1, 2]  # HashValue SHA256 + payload
                         )
        self.assertEqual(expected, actual)

    def test_unencrypted_nopts_node(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        node = Node(hash_groups=[hg])
        factory = ManifestFactory(self._create_options())
        manifest = factory.build(node)
        actual = manifest.serialize()

        expected = array('B', [0, 2, 0, 14,   # Node
                               0, 2, 0, 10,   # HashGroup
                               0, 2, 0,  6,   # Pointers
                               0, 1, 0,  2, 1, 2]  # HashValue SHA256 + payload
                         )
        self.assertEqual(expected, actual)

    def test_unencrypted_opts_pointers(self):
        tree_options = self._create_options(add_group_subtree_size=True, add_node_subtree_size=True)
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        factory = ManifestFactory(tree_options=tree_options)
        manifest = factory.build(ptr, node_subtree_size=20, group_subtree_size=16)
        actual = manifest.serialize()

        expected = array('B', [0, 2, 0, 46,   # Node
                               0, 1, 0, 12,   # NodeData
                               0, 1, 0,  8,   # SubtreeSize
                               0, 0, 0, 0, 0, 0, 0, 20,
                               0, 2, 0, 26,   # HashGroup
                               0, 1, 0, 12,   # GroupData
                               0, 1, 0,  8,   # SubtreeSize
                               0, 0, 0, 0, 0, 0, 0, 16,
                               0, 2, 0,  6,   # Pointers
                               0, 1, 0,  2, 1, 2]  # HashValue SHA256 + payload
                         )
        self.assertEqual(expected, actual)

    def test_unencrypted_opts_hashgroup(self):
        tree_options = self._create_options(add_group_subtree_size=True, add_node_subtree_size=True)
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        hg = HashGroup(pointers=ptr)
        factory = ManifestFactory(tree_options=tree_options)
        manifest = factory.build(hg, node_subtree_size=20, group_subtree_size=16)
        actual = manifest.serialize()

        # Note that we did not add a GroupData to the HashGroup, so it is missing even though
        # the options asked to put it in.
        expected = array('B', [0, 2, 0, 30,   # Node
                               0, 1, 0, 12,   # NodeData
                               0, 1, 0,  8,   # SubtreeSize
                               0, 0, 0, 0, 0, 0, 0, 20,
                               0, 2, 0, 10,   # HashGroup
                               0, 2, 0,  6,   # Pointers
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
        manifest = factory.build(node)

        self.assertTrue(manifest.is_encrypted())

        decryptor = AeadDecryptor(key, 99)
        actual_manifest = decryptor.decrypt_manifest(manifest)

        self.assertEqual(node, actual_manifest.node())

    def test_nc_defs(self):
        hv = HashValue.create_sha256([1, 2])
        ptr = Pointers([hv])
        factory = ManifestFactory(self._create_options())
        nc_def = NcDef(nc_id=NcId(7), schema=PrefixSchema(name=Name.from_uri('ccnx:/a')))
        manifest = factory.build(source=ptr, nc_defs=[nc_def])
        actual = manifest.serialize()

        expected = array('B',[
                    # Node
                    0, 2, 0, 40,
                        # Node Data
                        0, 1, 0, 22,
                            # NcDef
                            0, 6, 0, 18,
                                # ncid
                                0, 16, 0, 1, 7,
                                    # prefix schema
                                    0, 3, 0, 9,
                                    # name
                                    0, 0, 0, 5, 0, 1, 0, 1, 97,
                        # hash group
                        0, 2, 0, 10,
                            # pointers
                            0, 2, 0, 6,
                                # hash value
                                0, 1, 0, 2, 1, 2
                         ])
        self.assertEqual(expected, actual)


