#  Copyright 2019 Marc Mosko
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
import ccnpy
import ccnpy.crypto
import ccnpy.flic
import ccnpy.flic.presharedkey
import ccnpy.flic.tree


class test_TreeParameters(unittest.TestCase):
    def test_unencrypted_maxsize(self):
        hv = ccnpy.HashValue.create_sha256(32*[0])
        factory = ccnpy.flic.ManifestFactory()
        chunks = ccnpy.flic.Pointers(hash_values=1000*[hv])
        max_packet_size = 1500
        params = ccnpy.flic.tree.TreeParameters.create_optimized_tree(file_chunks=chunks,
                                                                      max_packet_size=max_packet_size,
                                                                      manifest_factory=factory)

        piece = ccnpy.flic.Pointers(hash_values=params.num_pointers_per_node()*[hv])
        packet = factory.build_packet(source=piece)
        self.assertTrue(len(packet) < max_packet_size)
        self.assertEqual(40, params.num_pointers_per_node())

    def test_encrypted_maxsize(self):
        key=ccnpy.crypto.AesGcmKey.generate(128)
        encryptor=ccnpy.flic.presharedkey.PresharedKeyEncryptor(key=key, key_number=22)
        hv = ccnpy.HashValue.create_sha256(32*[0])
        factory = ccnpy.flic.ManifestFactory(encryptor=encryptor)
        chunks = ccnpy.flic.Pointers(hash_values=1000*[hv])
        max_packet_size = 1500
        params = ccnpy.flic.tree.TreeParameters.create_optimized_tree(file_chunks=chunks,
                                                                      max_packet_size=max_packet_size,
                                                                      manifest_factory=factory)

        piece = ccnpy.flic.Pointers(hash_values=params.num_pointers_per_node()*[hv])
        packet = factory.build_packet(source=piece)
        self.assertTrue(len(packet) < max_packet_size)
        self.assertEqual(38, params.num_pointers_per_node())
