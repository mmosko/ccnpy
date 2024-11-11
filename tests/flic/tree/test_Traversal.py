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

from ccnpy.core.ContentObject import ContentObject
from ccnpy.core.Packet import Packet, PacketReader
from ccnpy.core.Payload import Payload
from ccnpy.crypto.AeadKey import AeadGcm
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.flic.ManifestEncryptor import ManifestEncryptor
from ccnpy.flic.ManifestFactory import ManifestFactory
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.name_constructor.HashSchemaImpl import HashSchemaImpl
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import HashSchema
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeBuilder import TreeBuilder
from ccnpy.flic.tree.TreeIO import TreeIO
from ccnpy.flic.tree.TreeParameters import TreeParameters
from tests.MockChunker import create_file_chunks


class TraversalTest(unittest.TestCase):
    # TODO: This test does not iterate over internal manifests, it only tests leafs.

    def setUp(self):
        self.hash_schema = HashSchemaImpl(nc_id=NcId(1), schema=HashSchema(locators=Locators.from_uri('ccnx:/a')), tree_options=None)

    @staticmethod
    def _create_options(max_packet_size: int, encryptor: Optional[ManifestEncryptor] = None):
        return ManifestTreeOptions(max_packet_size=max_packet_size,
                                   name=None,
                                   schema_type=SchemaType.HASHED,
                                   signer=None,
                                   manifest_encryptor=encryptor)

    def _create_tree_builder(self, metadata, solution, packet_buffer, encryptor=None):
        tree_options = self._create_options(max_packet_size=1500, encryptor=encryptor)
        params = TreeParameters(file_metadata=metadata, max_packet_size=tree_options.max_packet_size, solution=solution)
        factory = ManifestFactory(tree_options=tree_options)

        return TreeBuilder(file_metadata=metadata,
                           tree_parameters=params,
                           manifest_factory=factory,
                           packet_output=packet_buffer,
                           tree_options=tree_options)


    @staticmethod
    def _create_data_packet(application_data):
        payload = Payload(application_data)
        packet = Packet.create_content_object(ContentObject.create_data(payload=payload))
        return packet

    @classmethod
    def _create_manifest_from_packets(cls, packets: PacketReader, tree_options: ManifestTreeOptions):
        pointers = []
        for packet in packets:
            pointers.append(packet.content_object_hash())
        manifest = ManifestFactory(tree_options=tree_options).build(Pointers(pointers), nc_id=NcId(1))
        return manifest

    def test_data_node(self):
        """
        A single data node
        :return:
        """
        expected = array("B", [1, 2, 3, 4, 5])
        packet = self._create_data_packet(expected)

        buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=buffer, packet_input=None)
        traversal.preorder(packet, nc_cache=Traversal.NameConstructorCache(copy={1: self.hash_schema}))
        self.assertEqual(expected, buffer.buffer)

    def test_leaf_manifest(self):
        """
        A manifest with only data pointers
        :return:
        """
        expected = array("B", list(range(1, 8)))
        packet_buffer = TreeIO.PacketMemoryWriter()
        create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        tree_options = self._create_options(max_packet_size=1500)
        manifest = self._create_manifest_from_packets(packets=packet_buffer, tree_options=tree_options)

        root = Packet.create_content_object(manifest.content_object())

        # The reconstructed application data
        buffer = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=buffer, packet_input=packet_buffer)
        traversal.preorder(root, nc_cache=Traversal.NameConstructorCache(copy={1: self.hash_schema}))
        self.assertEqual(expected, buffer.buffer)

    def test_encrypted_leaf_manifest(self):
        key = AeadGcm.generate(bits=128)
        encryptor = AeadEncryptor(key=key, key_number=77)
        decryptor = AeadDecryptor(key=key, key_number=77)

        # This size needs to be small enough that all the pointers fit in one manifest.
        expected = array("B", range(0, 30))
        packet_buffer = TreeIO.PacketMemoryWriter()
        create_file_chunks(data=expected, packet_buffer=packet_buffer, max_chunk_size=1)

        tree_options = self._create_options(max_packet_size=1500, encryptor=encryptor)
        manifest = self._create_manifest_from_packets(packets=packet_buffer, tree_options=tree_options)

        root = Packet.create_content_object(manifest.content_object())

        # The reconstructed application data
        buffer = TreeIO.DataBuffer()
        keystore = InsecureKeystore().add_aes_key(key_num=77, key=key, salt=None)
        traversal = Traversal(data_writer=buffer, packet_input=packet_buffer, keystore=keystore)
        traversal.preorder(root, nc_cache=Traversal.NameConstructorCache(copy={1: self.hash_schema}))
        self.assertEqual(expected, buffer.buffer)


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(TraversalTest())
