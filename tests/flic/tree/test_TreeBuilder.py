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


from tests.ccnpy_testcase import CcnpyTestCase
from array import array
from typing import Optional

from ccnpy.core.Name import Name
from ccnpy.crypto.AeadKey import AeadCcm
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.flic.ManifestEncryptor import ManifestEncryptor
from ccnpy.flic.ManifestFactory import ManifestFactory
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.name_constructor.NameConstructorContext import NameConstructorContext
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tree.ManifestGraph import ManifestGraph
from ccnpy.flic.tree.OptimizerResult import OptimizerResult
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeBuilder import TreeBuilder
from ccnpy.flic.tree.TreeIO import TreeIO
from ccnpy.flic.tree.TreeParameters import TreeParameters
from tests.MockChunker import create_file_chunks
from tests.MockReader import MockReader


class TreeBuilderTest(CcnpyTestCase):

    @staticmethod
    def _create_options(max_packet_size: int, encryptor: Optional[ManifestEncryptor]):
        return ManifestTreeOptions(max_packet_size=max_packet_size,
                                   name=Name.from_uri('ccnx:/a'),
                                   schema_type=SchemaType.HASHED,
                                   signer=None,
                                   manifest_encryptor=encryptor,
                                   debug=False)

    def _create_tree_builder(self, metadata, solution, packet_buffer, encryptor=None, graph=None) -> TreeBuilder:
        tree_options = self._create_options(max_packet_size=1500, encryptor=encryptor)
        params = TreeParameters(file_metadata=metadata, max_packet_size=tree_options.max_packet_size, solution=solution)
        factory = ManifestFactory(tree_options=tree_options)

        return TreeBuilder(file_metadata=metadata,
                           tree_parameters=params,
                           manifest_factory=factory,
                           packet_output=packet_buffer,
                           tree_options=tree_options,
                           name_ctx=NameConstructorContext.create(tree_options=tree_options),
                           manifest_graph=graph)

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

        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer)
        traversal.preorder(packet=top_packet,
                           nc_cache=Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 15 manifest nodes and 15 data nodes
        self.assertEqual(30, traversal.count())
        self.assertEqual(3, solution.tree_height())

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
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer)
        traversal.preorder(top_manifest, Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 7 manifest nodes and 15 data nodes
        self.assertEqual(22, traversal.count())
        self.assertEqual(2, solution.tree_height())

    def test_nary_4_3_61(self):
        """
            ```
            Example:
                DDDDMMM
                  _/  ||_____________________________
                 /     |___                          |
                /          |                          |
                DDDDDDD     DDDDMMM                   DDDDMMM
                         __/ ||                    __/ ||
                        /     ||________          /     ||________
                       /       |        |        /       |        |
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
        self.assertEqual(2, solution.tree_height())

    def test_less_large_optimized_segmented(self):
        """
        A larger example using an optimized tree to minimize the tree waste
        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", [x % 256 for x in range(0, 1000)])
        metadata = create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        tree_options = ManifestTreeOptions(max_packet_size=1500,
                                           name=Name.from_uri('ccnx:/a'),
                                           schema_type=SchemaType.SEGMENTED,
                                           signer=None,
                                           manifest_encryptor=None,
                                           manifest_prefix=Name.from_uri('ccnx:/a'),
                                           data_prefix=Name.from_uri('ccnx:/b'),
                                           debug=False)

        factory = ManifestFactory(tree_options=tree_options)
        name_ctx = NameConstructorContext.create(tree_options)
        params = TreeParameters.create_optimized_tree(file_metadata=metadata, manifest_factory=factory, name_ctx=name_ctx)
        print(params)

        g = ManifestGraph()
        tb = TreeBuilder(file_metadata=metadata,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer,
                         tree_options=tree_options,
                         name_ctx=name_ctx,
                         manifest_graph=g)
        top_packet = tb.build()
        g.save('midtree.dot')

        expected_top_name = Name.from_uri('ccnx:/a').append_manifest_id(0)
        self.assertEqual(expected_top_name, top_packet.body().name())

        print(name_ctx)

        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer, build_graph=True)
        traversal.preorder(top_packet, Traversal.NameConstructorCache(name_ctx.export_schemas()))
        # traversal.get_graph().plot()
        self.assertEqual(expected, data_buffer.buffer)

        # 27 manifest plus 1000 data objects
        self.assertEqual(1027, traversal.count())

        # 13-ary tree with 28 manifests is max height 1 (i.e. top + next level)
        self.assertEqual(1, params.tree_height())

    def test_segmented_tree(self):
        """
        Use a large packet size, but limit the tree degree to 3.

        solution={OptResult n=23, p=3, dir=1, ind=2, int=5, leaf=6, w=0, h=4}
        :return:
        """
        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        packet_buffer = TreeIO.PacketMemoryWriter()
        data_input = MockReader(data=array("B", [x % 256 for x in range(0, 8000)]))
        max_packet_size=400

        tree_options = ManifestTreeOptions(name=Name.from_uri("ccnx:/example.com/manifest"),
                                          schema_type=SchemaType.SEGMENTED,
                                          manifest_prefix=Name.from_uri('ccnx:/manifest'),
                                          data_prefix=Name.from_uri('ccnx:/data'),
                                          signer=None,
                                          max_packet_size=max_packet_size,
                                          max_tree_degree=3,
                                          debug=False)

        factory = ManifestFactory(tree_options=tree_options)
        name_ctx = NameConstructorContext.create(tree_options)
        metadata = name_ctx.data_schema_impl.chunk_data(data_input, packet_buffer)

        params = TreeParameters.create_optimized_tree(file_metadata=metadata, manifest_factory=factory, name_ctx=name_ctx)
        print(params)

        g = ManifestGraph()
        tb = TreeBuilder(file_metadata=metadata,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer,
                         tree_options=tree_options,
                         name_ctx=name_ctx,
                         manifest_graph=g)
        top_packet = tb.build()
        g.save('segmentedtree.dot')

        expected_top_name = Name.from_uri('ccnx:/manifest').append_manifest_id(0)
        self.assertEqual(expected_top_name, top_packet.body().name())

        expected = data_input.data
        actual_data = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=actual_data, packet_input=packet_buffer, build_graph=False)
        traversal.preorder(top_packet, nc_cache=Traversal.NameConstructorCache(copy=name_ctx.export_schemas()))

        self.assertEqual(expected, actual_data.buffer)

        # We have 8000 bytes of data.
        # We get 353 bytes of data per data object, so there's 23 data objects.
        # We get 3 pointers per manifest, so we need leaf 8 manifests, plus the root, plus 3 internal
        # root -> top -> {m1, m2, m3} -> {leaf1, ..., leaf8}
        self.assertEqual(23, actual_data.count)

        # 23 data  + top + 3 internal + 8 leaf = 35
        self.assertEqual(35, len(packet_buffer))

        # self._test_root_manifest(top_packet)
        # self._test_top_manifest(self.packet_buffer.packets[-2])

    def test_large_optimized(self):
        """
        A larger example using an optimized tree to minimize the tree waste

        solution={OptResult n=5000, p=39, dir=6, ind=33, int=4, leaf=128, w=55, h=2}

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()
        expected = array("B", [x % 256 for x in range(0, 5000)])
        metadata = create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        tree_options = ManifestTreeOptions(max_packet_size=1500,
                                           name=Name.from_uri('ccnx:/a'),
                                           schema_type=SchemaType.SEGMENTED,
                                           signer=None,
                                           manifest_encryptor=None,
                                           manifest_prefix=Name.from_uri('ccnx:/a'),
                                           data_prefix=Name.from_uri('ccnx:/b'),
                                           debug=False)

        factory = ManifestFactory(tree_options=tree_options)
        name_ctx = NameConstructorContext.create(tree_options)
        params = TreeParameters.create_optimized_tree(file_metadata=metadata, manifest_factory=factory, name_ctx=name_ctx)
        print(params)

        g = ManifestGraph()
        tb = TreeBuilder(file_metadata=metadata,
                         tree_parameters=params,
                         manifest_factory=factory,
                         packet_output=packet_buffer,
                         tree_options=tree_options,
                         name_ctx=name_ctx,
                         manifest_graph=g)
        top_packet = tb.build()
        g.save('largetree.dot')

        expected_top_name = Name.from_uri('ccnx:/a').append_manifest_id(0)
        self.assertEqual(expected_top_name, top_packet.body().name())
        print(name_ctx)

        data_buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer, build_graph=True)
        traversal.preorder(top_packet, Traversal.NameConstructorCache(name_ctx.export_schemas()))
        # traversal.get_graph().plot()
        self.assertEqual(expected, data_buffer.buffer)

        # 136 manifest nodes and 5000 data nodes
        self.assertEqual(5133, traversal.count())

        # 15-ary tree with 136 manifests => ceil(log_13(136)) = 2
        self.assertEqual(2, params.tree_height())

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
        encryptor = AeadEncryptor(AeadParameters(key=key, key_number=1234))

        tb = self._create_tree_builder(metadata=metadata, solution=solution, packet_buffer=packet_buffer,
                                       encryptor=encryptor)

        top_manifest = tb.build()
        data_buffer = TreeIO.DataBuffer()
        keystore = InsecureKeystore()
        keystore.add_aes_key(AeadParameters(key_number=1234, key=key, aead_salt=None))
        traversal = Traversal(data_writer=data_buffer, packet_input=packet_buffer, keystore=keystore)
        traversal.preorder(top_manifest, Traversal.NameConstructorCache(tb.name_context().export_schemas()))
        self.assertEqual(expected, data_buffer.buffer)

        # 15 manifest nodes and 15 data nodes
        self.assertEqual(30, traversal.count())
