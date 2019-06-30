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
from array import array

import ccnpy
import ccnpy.crypto
import ccnpy.flic
import ccnpy.flic.presharedkey
import ccnpy.flic.tree
from ccnpy.flic.tree import TreeIO


class test_Traversal(unittest.TestCase):
    @staticmethod
    def _create_data_packet(application_data):
        payload = ccnpy.Payload(application_data)
        packet = ccnpy.Packet.create_content_object(ccnpy.ContentObject.create_data(payload=payload))
        return packet

    @classmethod
    def _create_manifest_from_packets(cls, packets, encryptor=None):
        pointers = []
        for packet in packets:
            pointers.append(packet.content_object_hash())
        manifest = ccnpy.flic.ManifestFactory(encryptor=encryptor).build(ccnpy.flic.Pointers(pointers))
        return manifest

    def test_data_node(self):
        """
        A single data node
        :return:
        """
        expected = array("B", [1, 2, 3, 4, 5])
        packet = self._create_data_packet(expected)

        buffer = TreeIO.DataBuffer()
        traversal = ccnpy.flic.tree.Traversal(data_buffer=buffer, packet_input=None)
        traversal.preorder(packet)
        self.assertEqual(expected, buffer.buffer)

    def test_leaf_manifest(self):
        """
        A manifest with only data pointers
        :return:
        """
        expected = array("B", [1, 2, 3, 4, 5, 6, 7])
        data_packets = TreeIO.chunk_data_to_packets(expected, 2)
        manifest = self._create_manifest_from_packets(data_packets)
        root = ccnpy.Packet.create_content_object(manifest.content_object())

        packet_input = TreeIO.PacketMemoryReader(data_packets)
        buffer = TreeIO.DataBuffer()
        traversal = ccnpy.flic.tree.Traversal(data_buffer=buffer, packet_input=packet_input)
        traversal.preorder(root)
        self.assertEqual(expected, buffer.buffer)

    def test_encrypted_manifest(self):
        key = ccnpy.crypto.AesGcmKey.generate(bits=128)
        encryptor = ccnpy.flic.presharedkey.PresharedKeyEncryptor(key=key, key_number=77)
        decryptor = ccnpy.flic.presharedkey.PresharedKeyDecryptor(key=key, key_number=77)

        expected = array("B", [1, 2, 3, 4, 5, 6, 7])
        data_packets = TreeIO.chunk_data_to_packets(expected, 2)
        manifest = self._create_manifest_from_packets(packets=data_packets, encryptor=encryptor)
        root = ccnpy.Packet.create_content_object(manifest.content_object())

        packet_input = TreeIO.PacketMemoryReader(data_packets)
        buffer = TreeIO.DataBuffer()
        traversal = ccnpy.flic.tree.Traversal(data_buffer=buffer, packet_input=packet_input, decryptor=decryptor)
        traversal.preorder(root)
        self.assertEqual(expected, buffer.buffer)

