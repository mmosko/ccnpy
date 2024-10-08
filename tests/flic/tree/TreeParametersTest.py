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

from ccnpy.core.HashValue import HashValue
from ccnpy.crypto.AeadKey import AeadGcm
from ccnpy.flic.ManifestFactory import ManifestFactory
from ccnpy.flic.Pointers import Pointers
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.tree.TreeParameters import TreeParameters


class TreeParametersTest(unittest.TestCase):
    def test_unencrypted_maxsize(self):
        hv = HashValue.create_sha256(32 * [0])
        factory = ManifestFactory()
        chunks = Pointers(hash_values=1000 * [hv])
        max_packet_size = 1500
        params = TreeParameters.create_optimized_tree(file_chunks=chunks,
                                                      max_packet_size=max_packet_size,
                                                      manifest_factory=factory)

        piece = Pointers(hash_values=params.num_pointers_per_node() * [hv])
        packet = factory.build_packet(source=piece)
        self.assertTrue(len(packet) < max_packet_size)
        self.assertEqual(40, params.num_pointers_per_node())

    def test_encrypted_maxsize(self):
        key = AeadGcm.generate(128)
        encryptor = AeadEncryptor(key=key, key_number=22)
        hv = HashValue.create_sha256(32 * [0])
        factory = ManifestFactory(encryptor=encryptor)
        chunks = Pointers(hash_values=1000 * [hv])
        max_packet_size = 1500
        params = TreeParameters.create_optimized_tree(file_chunks=chunks,
                                                      max_packet_size=max_packet_size,
                                                      manifest_factory=factory)

        piece = Pointers(hash_values=params.num_pointers_per_node() * [hv])
        packet = factory.build_packet(source=piece)
        self.assertTrue(len(packet) < max_packet_size)
        self.assertEqual(38, params.num_pointers_per_node())
