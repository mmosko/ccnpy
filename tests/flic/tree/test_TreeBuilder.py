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


import functools
import operator
import struct
import unittest
from array import array

from ccnpy.core.Packet import Packet
from ccnpy.flic.tree.FileChunks import FileChunks
from ccnpy.flic.tree.SizedPointer import SizedPointer
from ccnpy.flic.tree.Solution import Solution
from ccnpy.flic.tree.TreeIO import TreeIO
from ccnpy.flic.tree.TreeParameters import TreeParameters

from ccnpy.crypto.AesGcmKey import AesGcmKey
from ccnpy.flic.ManifestFactory import ManifestFactory
from ccnpy.flic.presharedkey.PresharedKeyDecryptor import PresharedKeyDecryptor
from ccnpy.flic.presharedkey.PresharedKeyEncryptor import PresharedKeyEncryptor
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeBuilder import TreeBuilder


class TreeBuilderTest(unittest.TestCase):
    @staticmethod
    def _contentobject_from_packet(packet):
        assert isinstance(packet, Packet)
        return packet.body()

    @staticmethod
    def _is_packet_manifest(packet):
        result = False
        body = packet.body()
        if body.is_content_object():
            if body.payload_type().is_manifest():
                result = True
        return result

    @staticmethod
    def _create_file_chunks(packet_buffer, data, length=1000, chunk_size=1):
        chunks = FileChunks()
        packets = TreeIO.chunk_data_to_packets(data, chunk_size)
        for packet in packets:
            packet_buffer.put(packet)
            hv = packet.content_object_hash()
            manifest_pointer = SizedPointer(hv, length)
            chunks.append(manifest_pointer)

        return chunks

    def test_binary_0_2_15(self):
        """
        A binary (0, 2) tree with 15 direct pointers.  Note there is no storage at internal nodes, so
        this tree should be height 3.

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", list(range(0, 15)))
        data = self._create_file_chunks(packet_buffer=packet_buffer, data=expected)

        solution = Solution(total_direct_nodes=len(data),
                            num_pointers=2,
                            direct_per_node=0,
                            indirect_per_node=2,
                            num_internal_nodes=None,
                            waste=None)

        params = TreeParameters(data, 1500, solution)

        factory = ManifestFactory()

        tb = TreeBuilder(file_chunks=data,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer)
        root = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_buffer=data_buffer, packet_input=packet_buffer)
        traversal.preorder(root)
        self.assertEqual(expected, data_buffer.buffer)

        # 15 manifest nodes and 15 data nodes
        self.assertEqual(30, traversal.count())

    def test_binary_1_2_15(self):
        """
        Test a binary (1,2) tree with 15 direct pointers.  This stores 1 data element at each tree node
        plus up to 2 children per node (so it's really a ternary tree).

        3 internal nodes + 4 leaf nodes = 3 + 12 = 15 data pointers in 7 nodes

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", list(range(0, 16)))
        data = self._create_file_chunks(packet_buffer=packet_buffer, data=expected)

        solution = Solution(total_direct_nodes=len(data),
                            num_pointers=3,
                            direct_per_node=1,
                            indirect_per_node=2,
                            num_internal_nodes=None,
                            waste=None)

        params = TreeParameters(data, 1500, solution)

        factory = ManifestFactory()

        tb = TreeBuilder(file_chunks=data,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer)
        root = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_buffer=data_buffer, packet_input=packet_buffer)
        #traversal.debug = True
        traversal.preorder(root)
        self.assertEqual(expected, data_buffer.buffer)

        # 8 manifest nodes and 16 data nodes
        self.assertEqual(24, traversal.count())

    def test_nary_4_3_61(self):
        """
            ```
            Example:
                DDDDMMM
                  _/  \\_____________________________
                 /     \___                          \
                /          \                          \
                DDDDDDD     DDDDMMM                   DDDDMMM
                         __/ \\                    __/ \\
                        /     \\________          /     \\________
                       /       \        \        /       \        \
                      DDDDDDD  DDDDDDD  DDDDDDD DDDDDDD  DDDDDDD  DDDDDDD

                3 * 4 + 7 * 7 = 12 + 49 = 61
                n = 61, so h = 1.77 -> h = 2
            ```
        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", list(range(0, 61)))
        data = self._create_file_chunks(packet_buffer=packet_buffer, data=expected)

        solution = Solution(total_direct_nodes=len(data),
                            num_pointers=7,
                            direct_per_node=4,
                            indirect_per_node=3,
                            num_internal_nodes=None,
                            waste=None)

        params = TreeParameters(data, 1500, solution)

        factory = ManifestFactory()

        tb = TreeBuilder(file_chunks=data,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer)
        root = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_buffer=data_buffer, packet_input=packet_buffer)
        traversal.preorder(root)
        self.assertEqual(expected, data_buffer.buffer)

        # 10 manifest nodes and 61 data nodes
        self.assertEqual(71, traversal.count())

    def test_large_optimized(self):
        """
        A larger example using an optimized tree to minimize the tree waste
        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()

        # Creates an array of 2-byte words
        expected = array("B", functools.reduce(operator.iconcat,
                                               # This creates a list of arrays that need to be flattened
                                               [array("B", struct.pack("!H", x)) for x in range(0, 5000)],
                                               []))

        data = self._create_file_chunks(packet_buffer=packet_buffer, data=expected, chunk_size=2)

        solution = Solution(total_direct_nodes=len(data),
                            num_pointers=41,
                            direct_per_node=37,
                            indirect_per_node=4,
                            num_internal_nodes=None,
                            waste=None)

        params = TreeParameters(data, 1500, solution)

        factory = ManifestFactory()

        tb = TreeBuilder(file_chunks=data,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer)
        root = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_buffer=data_buffer, packet_input=packet_buffer)
        traversal.preorder(root)
        self.assertEqual(expected, data_buffer.buffer)

        # 126 manifest nodes and 5000 data nodes
        self.assertEqual(5126, traversal.count())

    def test_encrypted_0_2_15(self):
        """
        A binary (0, 2) tree with 15 direct pointers.  Note there is no storage at internal nodes, so
        this tree should be height 3.  This time do it encrypted.

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", list(range(0, 15)))
        data = self._create_file_chunks(packet_buffer=packet_buffer, data=expected)

        solution = Solution(total_direct_nodes=len(data),
                            num_pointers=2,
                            direct_per_node=0,
                            indirect_per_node=2,
                            num_internal_nodes=None,
                            waste=None)

        params = TreeParameters(data, 1500, solution)

        key = AesGcmKey.generate(bits=256)
        encryptor = PresharedKeyEncryptor(key=key, key_number=1234)
        decryptor = PresharedKeyDecryptor(key=key, key_number=1234)

        factory = ManifestFactory(encryptor=encryptor)

        tb = TreeBuilder(file_chunks=data,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer)
        root = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_buffer=data_buffer, packet_input=packet_buffer, decryptor=decryptor)
        traversal.preorder(root)
        self.assertEqual(expected, data_buffer.buffer)

        # 15 manifest nodes and 15 data nodes
        self.assertEqual(30, traversal.count())
