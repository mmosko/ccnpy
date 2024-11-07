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
from typing import Optional

from ccnpy.core.HashValue import HashValue
from ccnpy.crypto.AeadKey import AeadGcm
from ccnpy.flic.ManifestEncryptor import ManifestEncryptor
from ccnpy.flic.ManifestFactory import ManifestFactory
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.FileMetadata import FileMetadata, ChunkMetadata
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.tree.TreeParameters import TreeParameters


class TreeParametersTest(unittest.TestCase):

    @staticmethod
    def _create_options(max_packet_size: int, encryptor: Optional[ManifestEncryptor] = None):
        return ManifestTreeOptions(max_packet_size=max_packet_size,
                                   name=None,
                                   schema_type=SchemaType.HASHED,
                                   signer=None,
                                   manifest_encryptor=encryptor)

    def setUp(self):
        self.hv = HashValue.create_sha256(32 * [0])
        self.file_metadata = FileMetadata(
            chunk_metadata = [ChunkMetadata(chunk_number=x, payload_bytes=1000, content_object_hash=self.hv) for x in range(0,1000)],
            total_bytes = 1000 * 1000
        )
        self.max_packet_size = 1500

    def test_unencrypted_maxsize(self):

        factory = ManifestFactory(tree_options=self._create_options(max_packet_size=self.max_packet_size))
        params = TreeParameters.create_optimized_tree(file_metadata=self.file_metadata,
                                                      max_packet_size=self.max_packet_size,
                                                      manifest_factory=factory)

        piece = Pointers(hash_values=params.num_pointers_per_node() * [self.hv])
        packet = factory.build_packet(source=piece)
        self.assertTrue(len(packet) < self.max_packet_size)
        self.assertEqual(40, params.num_pointers_per_node())

    def test_encrypted_maxsize(self):
        key = AeadGcm.generate(128)
        encryptor = AeadEncryptor(key=key, key_number=22)

        factory = ManifestFactory(tree_options=self._create_options(max_packet_size=self.max_packet_size, encryptor=encryptor))

        params = TreeParameters.create_optimized_tree(file_metadata=self.file_metadata,
                                                      max_packet_size=self.max_packet_size,
                                                      manifest_factory=factory)

        piece = Pointers(hash_values=params.num_pointers_per_node() * [self.hv])
        packet = factory.build_packet(source=piece)
        self.assertTrue(len(packet) < self.max_packet_size)
        self.assertEqual(39, params.num_pointers_per_node())
