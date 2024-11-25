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


import io
import unittest
from array import array
from binascii import unhexlify

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Name import Name
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256Signer
from ccnpy.flic.ManifestTree import ManifestTree
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.SchemaImplFactory import SchemaImplFactory
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.NcDef import NcDef
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import SegmentedSchema
from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.NodeData import NodeData
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.StartSegmentId import StartSegmentId
from ccnpy.flic.tree.ManifestGraph import ManifestGraph
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeIO import TreeIO
from tests.MockKeys import private_key_pem
from tests.MockReader import MockReader


class test_ManifestTree(unittest.TestCase):


    def setUp(self):
        SchemaImplFactory.reset_nc_id()
        self.packet_buffer = TreeIO.PacketMemoryWriter()
        self.rsa_key = RsaKey(pem_key=private_key_pem)
        self.root_signer = RsaSha256Signer(key=self.rsa_key)

    def _create_options(self, max_packet_size, schema_type=SchemaType.HASHED):
        if schema_type == SchemaType.HASHED:
            return ManifestTreeOptions(name=Name.from_uri("ccnx:/example.com/manifest"),
                                          schema_type=schema_type,
                                          manifest_locators=Locators.from_uri('ccnx:/x/y'),
                                          signer=self.root_signer,
                                          max_packet_size=max_packet_size,
                                          max_tree_degree=3,
                                          debug=False)
        else:
            return ManifestTreeOptions(name=Name.from_uri("ccnx:/example.com/manifest"),
                                          schema_type=schema_type,
                                          manifest_prefix=Name.from_uri('ccnx:/manifest'),
                                          data_prefix=Name.from_uri('ccnx:/data'),
                                          signer=self.root_signer,
                                          max_packet_size=max_packet_size,
                                          max_tree_degree=3,
                                          debug=False)

    def test_nary_1_2_14(self):
        """
        3-way tree with 2 direct and 1 indirect per node.

        :return:
        """
        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = io.BytesIO(private_key_pem)

        tree = ManifestTree(data_input=data_input,
                            packet_output=self.packet_buffer,
                            tree_options=self._create_options(250))

        root_manifest = tree.build()

        expected = array("B", private_key_pem)
        actual_data = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=actual_data, packet_input=self.packet_buffer, build_graph=False)
        traversal.preorder(root_manifest, nc_cache=Traversal.NameConstructorCache(copy=tree.name_context().export_schemas()))
        # traversal.get_graph().save('tree.dot')

        self.assertEqual(expected, actual_data.buffer)
        self.assertEqual(8, actual_data.count)

        # 13 = 8 data objects + 1 top + 3 interior + 1 leaf
        self.assertEqual(13, len(self.packet_buffer))

    def test_max_tree_degree(self):
        """
        Use a large packet size, but limit the tree degree to 3.
        :return:
        """
        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = io.BytesIO(private_key_pem)

        tree = ManifestTree(data_input=data_input,
                            packet_output=self.packet_buffer,
                            tree_options=self._create_options(400))

        root_manifest = tree.build()

        expected = array("B", private_key_pem)
        actual_data = TreeIO.DataBuffer()

        traversal = Traversal(data_writer=actual_data, packet_input=self.packet_buffer)
        traversal.preorder(root_manifest, nc_cache=Traversal.NameConstructorCache(copy=tree.name_context().export_schemas()))
        # We have 1674 bytes.  5 data objects plus 1 leaf manifests and 1 interior manifest

        self.assertEqual(expected, actual_data.buffer)
        self.assertEqual(5, actual_data.count)
        # 5 data nodes plus 1 leaf manifests plus 1 interior manifests plus 1 root manifest
        self.assertEqual(8, len(self.packet_buffer))

    def _test_root_manifest(self, actual_root_manifest_packet):
        expected_root_manifest = Manifest(
            node=Node(
                node_data=NodeData(nc_defs=[
                    NcDef(NcId(1), SegmentedSchema.create_for_manifest(Name.from_uri('ccnx:/manifest'))),
                    NcDef(NcId(2), SegmentedSchema.create_for_data(Name.from_uri('ccnx:/data'))),
                ]),
                hash_groups=[
                    HashGroup(
                        group_data=GroupData(nc_id=NcId(1), start_segment_id=StartSegmentId(0)),
                        pointers=Pointers([HashValue.create_sha256(unhexlify('3008e4c3eeedecdf4dba55aaa51f92d3534a57bf9d232011fcd3eb0485ec871a'))]))
                ]
            )
        )
        actual_root_manifest = Manifest.from_content_object(actual_root_manifest_packet.body())
        self.assertEqual(expected_root_manifest, actual_root_manifest)
        self.assertEqual(actual_root_manifest_packet.body().name(), Name.from_uri("ccnx:/example.com/manifest"))

    def _test_top_manifest(self, actual_top_manifest_packet):
        manifest_prefix = Name.from_uri('ccnx:/manifest')
        expected_top_manifest = Manifest(
            node=Node(
                hash_groups=[
                    HashGroup(
                        group_data=GroupData(nc_id=NcId(2), start_segment_id=StartSegmentId(0)),
                        pointers=Pointers([
                            HashValue.create_sha256(
                                unhexlify('eb96aebb6f998228f6d7060f50385d6378121522b9e13cfe98e1a39ebff3f4cc')),
                        ])),
                    HashGroup(
                        group_data=GroupData(nc_id=NcId(1), start_segment_id=StartSegmentId(1)),
                        pointers=Pointers([
                            HashValue.create_sha256(
                                unhexlify('10ca669f8505b78814a2b169a9b019b054e02a00ef6c98ac2d849ef20f0628a6')),
                            HashValue.create_sha256(
                                unhexlify('7809dd876472714225eaa79a3bb959ab8927619b5bb795f314bc66c9b2e95d62')),
                        ])),
                ]
            )
        )
        expected_top_packet = expected_top_manifest.packet(name=manifest_prefix.append_manifest_id(0))
        print(expected_top_packet)
        self.assertEqual(expected_top_packet, actual_top_manifest_packet)

    def test_segmented_tree(self):
        """
        Use a large packet size, but limit the tree degree to 3.

        solution={OptResult n=23, p=3, dir=1, ind=2, int=5, leaf=6, w=0, h=4}
        :return:
        """
        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = MockReader(data=array("B", [x % 256 for x in range(0, 8000)]))

        g = ManifestGraph()
        tree = ManifestTree(data_input=data_input,
                            packet_output=self.packet_buffer,
                            tree_options=self._create_options(400, SchemaType.SEGMENTED),
                            manifest_graph=g)
        root_manifest_packet = tree.build()
        # g.plot()

        expected = data_input.data
        actual_data = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=actual_data, packet_input=self.packet_buffer, debug=False, build_graph=True)
        traversal.preorder(root_manifest_packet, nc_cache=Traversal.NameConstructorCache(copy=tree.name_context().export_schemas()))
        # traversal.get_graph().plot()

        self.assertEqual(expected, actual_data.buffer)

        # We have 8000 bytes of data.
        # We get 353 bytes of data per data object, so there's 23 data objects.
        # We get 3 pointers per manifest, so we need leaf 8 manifests, plus the root, plus 3 internal
        # root -> top -> {m1, m2, m3} -> {leaf1, ..., leaf8}
        self.assertEqual(23, actual_data.count)

        # 23 data + root + top + 3 internal + 8 leaf = 36
        self.assertEqual(36, len(self.packet_buffer))

        self._test_root_manifest(root_manifest_packet)
        self._test_top_manifest(self.packet_buffer.packets[-2])

    def test_rsa_oaep(self):
        data_input = MockReader(data=array("B", [x % 256 for x in range(0, 500)]))

        options = ManifestTreeOptions(name=Name.from_uri("ccnx:/example.com/manifest"),
                                          schema_type=SchemaType.SEGMENTED,
                                          manifest_prefix=Name.from_uri('ccnx:/manifest'),
                                          data_prefix=Name.from_uri('ccnx:/data'),
                                          signer=self.root_signer,
                                          max_packet_size=400,
                                          max_tree_degree=3,
                                          debug=False)

        g = ManifestGraph()
        tree = ManifestTree(data_input=data_input,
                            packet_output=self.packet_buffer,
                            tree_options=options,
                            manifest_graph=g)
        root_manifest_packet = tree.build()
        # g.plot()
