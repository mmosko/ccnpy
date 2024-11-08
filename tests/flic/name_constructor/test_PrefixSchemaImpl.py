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


import array
import unittest

from ccnpy.core.ContentObject import ContentObject
from ccnpy.core.Name import Name
from ccnpy.core.Packet import Packet
from ccnpy.core.Payload import Payload
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256Signer
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.FileMetadata import FileMetadata, ChunkMetadata
from ccnpy.flic.name_constructor.PrefixSchemaImpl import PrefixSchemaImpl
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import PrefixSchema
from ccnpy.flic.tree.TreeIO import TreeIO
from tests.MockReader import MockReader
from tests.crypto.test_RsaSha256 import private_key_pem


class PrefixSchemaImplTest(unittest.TestCase):

    def setUp(self):
        self.nc_id = NcId(5)
        signer = RsaSha256Signer(RsaKey(private_key_pem))
        self.prefix = Name.from_uri('ccnx:/manifest/name')
        self.tree_options = ManifestTreeOptions(name=Name.from_uri('ccnx:/root/name'),
                                                schema_type=SchemaType.PREFIX,
                                                signer=signer)
        self.schema = PrefixSchema(name=self.prefix)
        self.impl = PrefixSchemaImpl(nc_id=self.nc_id, schema=self.schema, tree_options=self.tree_options)

    def test_get_name(self):
        actual = self.impl.get_name(7)
        expected = self.prefix
        self.assertEqual(expected, actual)

    def test_chunk_data(self):
        packet_buffer = TreeIO.PacketMemoryWriter()
        # a 2000 byte array with values in 0...255.
        application_data = array.array("B", [x % 256 for x in range(0, 2000)])
        mock_reader = MockReader(data=application_data)
        file_metadata = self.impl.chunk_data(data_input=mock_reader, packet_output=packet_buffer)

        expected_packets = TreeIO.PacketMemoryWriter()
        expected_packets.put(
            Packet.create_content_object(
                ContentObject.create_data(
                    name=self.prefix,
                 payload=Payload(application_data[0:1455]))))
        expected_packets.put(
            Packet.create_content_object(
                ContentObject.create_data(
                    name=self.prefix,
                    payload=Payload(application_data[1455:2000]))))
        self.assertEqual(expected_packets, packet_buffer)

        expected = FileMetadata(chunk_metadata=[ChunkMetadata(chunk_number=0,
                                                              payload_bytes=1455,
                                                              content_object_hash=expected_packets[0].content_object_hash()),
                                                ChunkMetadata(chunk_number=1,
                                                              payload_bytes=545,
                                                              content_object_hash=expected_packets[1].content_object_hash()),
                                                ],
                                total_bytes=2000)
        self.assertEqual(expected, file_metadata)

