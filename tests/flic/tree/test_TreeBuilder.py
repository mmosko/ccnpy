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
from typing import Optional

from ccnpy.core.Name import Name
from ccnpy.crypto.AeadKey import AeadCcm
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.flic.ManifestEncryptor import ManifestEncryptor
from ccnpy.flic.ManifestFactory import ManifestFactory
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.name_constructor.NameConstructorContext import NameConstructorContext
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tree.OptimizerResult import OptimizerResult
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeBuilder import TreeBuilder
from ccnpy.flic.tree.TreeIO import TreeIO
from ccnpy.flic.tree.TreeParameters import TreeParameters
from tests.MockChunker import create_file_chunks


class TreeBuilderTest(unittest.TestCase):

    @staticmethod
    def _create_options(max_packet_size: int, encryptor: Optional[ManifestEncryptor]):
        return ManifestTreeOptions(max_packet_size=max_packet_size,
                                   name=Name.from_uri('ccnx:/a'),
                                   schema_type=SchemaType.HASHED,
                                   signer=None,
                                   manifest_encryptor=encryptor,
                                   debug=False)

    def _create_tree_builder(self, metadata, solution, packet_buffer, encryptor=None) -> TreeBuilder:
        tree_options = self._create_options(max_packet_size=1500, encryptor=encryptor)
        params = TreeParameters(file_metadata=metadata, max_packet_size=tree_options.max_packet_size, solution=solution)
        factory = ManifestFactory(tree_options=tree_options)

        return TreeBuilder(file_metadata=metadata,
                           tree_parameters=params,
                           manifest_factory=factory,
                           packet_output=packet_buffer,
                           tree_options=tree_options,
                           name_ctx=NameConstructorContext.create(tree_options=tree_options))

    def test_binary_0_2_15(self):
        """
        A binary (0, 2) tree with 15 direct pointers.  Note there is no storage at internal nodes, so
        this tree should be height 4.  There are 15 manifest nodes.

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", list(range(0, 15)))
        metadata = create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        # binary tree with no direct storage in internal nodes
        solution = OptimizerResult(num_data_objects=len(metadata),
                                   num_pointers=2,
                                   direct_per_node=0,
                                   indirect_per_node=2,
                                   # 15 data objects with only leaf nodes => 8 leaf nodes, so 7 internal
                                   num_internal_nodes=7,
                                   waste=1)

        tb = self._create_tree_builder(metadata=metadata, solution=solution, packet_buffer=packet_buffer)

        top_packet = tb.build()
        data_buffer = TreeIO.DataBuffer()

        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer, debug=False)
        traversal.preorder(packet=top_packet, nc_cache=Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 15 manifest nodes and 15 data nodes
        self.assertEqual(30, traversal.count())
        self.assertEqual(4, solution.tree_height())

    def test_binary_1_2_15(self):
        """
        Test a binary (1,2) tree with 15 direct pointers.  This stores 1 data element at each tree node
        plus up to 2 children per node (so it's really a ternary tree).

        3 internal nodes + 4 leaf nodes = 3 + 12 = 15 data pointers in 7 nodes

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", list(range(0, 15)))
        metadata = create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        # ternary tree with up to 1 direct storage in internal nodes
        solution = OptimizerResult(num_data_objects=len(metadata),
                                   num_pointers=3,
                                   direct_per_node=1,
                                   indirect_per_node=2,
                                   num_internal_nodes=3,
                                   # 3 internal * 1 + 4 leaf * 3 = 15
                                   waste=0)

        tb = self._create_tree_builder(metadata=metadata, solution=solution, packet_buffer=packet_buffer)
        top_manifest = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer, debug=False)
        traversal.preorder(top_manifest, Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 7 manifest nodes and 15 data nodes
        self.assertEqual(22, traversal.count())
        # ceil(log_2(7)) = 3
        self.assertEqual(3, solution.tree_height())

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
        metadata = create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        # Tree as per the figure above
        solution = OptimizerResult(num_data_objects=len(metadata),
                                   num_pointers=7,
                                   direct_per_node=4,
                                   indirect_per_node=3,
                                   # 61 data objects => 3 internal * 4 direct + 7 leaf * 7 = 12 + 49 = 61 OK
                                   num_internal_nodes=3,
                                   waste=0)

        tb = self._create_tree_builder(metadata=metadata, solution=solution, packet_buffer=packet_buffer)

        top_manifest = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer)
        traversal.preorder(top_manifest, Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 10 manifest nodes and 61 data nodes
        self.assertEqual(71, traversal.count())
        # degree 3 with 10 manifests => ceil(log_3(10)) = 3
        self.assertEqual(3, solution.tree_height())

    def test_large_optimized(self):
        """
        A larger example using an optimized tree to minimize the tree waste
        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", [x % 256 for x in range(0, 5000)])
        metadata = create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        solution = OptimizerResult(num_data_objects=len(metadata),
                                   num_pointers=41,
                                   direct_per_node=37,
                                   indirect_per_node=4,
                                   # 5000 data objects.
                                   # 33 internal * 37 = 1221
                                   # 93 leaf * 41 = 3813
                                   # capacity = 5034
                                   # A 4-ary tree needs height 3 to accomodate up to 256 pointers
                                   # 1 + 4 + 16 + 12 internal => (16*4 - 12 + 12*4) = 100 available leaf manifest pointers,
                                   # so the tree is feasible (100 >= 93).
                                   num_internal_nodes=33,
                                   waste=34)

        tb = self._create_tree_builder(metadata=metadata, solution=solution, packet_buffer=packet_buffer)

        top_manifest = tb.build()
        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer)
        traversal.preorder(top_manifest, Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 126 manifest nodes and 5000 data nodes
        self.assertEqual(5126, traversal.count())

        # 4-ary tree with 126 manifests => ceil(log_4(126)) = 4
        self.assertEqual(4, solution.tree_height())

    def test_encrypted_0_2_15(self):
        """
        A binary (0, 2) tree with 15 direct pointers.  Note there is no storage at internal nodes, so
        this tree should be height 3.  This time do it encrypted.

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", list(range(0, 15)))
        metadata = create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        solution = OptimizerResult(num_data_objects=len(metadata),
                                   num_pointers=2,
                                   direct_per_node=0,
                                   indirect_per_node=2,
                                   # 15 data objects with only leaf nodes => 8 leaf nodes, so 7 internal
                                   num_internal_nodes=7,
                                   waste=1)

        key = AeadCcm.generate(bits=256)
        encryptor = AeadEncryptor(key=key, key_number=1234)

        tb = self._create_tree_builder(metadata=metadata, solution=solution, packet_buffer=packet_buffer, encryptor=encryptor)

        top_manifest = tb.build()
        data_buffer = TreeIO.DataBuffer()
        keystore = InsecureKeystore()
        keystore.add_aes_key(key_num=1234, key=key, salt=None)
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer, keystore=keystore)
        traversal.preorder(top_manifest, Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 15 manifest nodes and 15 data nodes
        self.assertEqual(30, traversal.count())
