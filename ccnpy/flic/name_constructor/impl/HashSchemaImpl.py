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

from typing import BinaryIO, List, Optional

from ..FileMetadata import FileMetadata, ChunkMetadata
from ..NcDef import NcDef
from ..NcId import NcId
from ..NcSchema import HashSchema, NcSchema
from ..SchemaType import SchemaType
from ..SchemaImpl import SchemaImpl
from ...Locators import Locators
from ...ManifestTreeOptions import ManifestTreeOptions
from ....core.ContentObject import ContentObject
from ....core.Name import Name
from ....core.Packet import Packet, PacketWriter
from ....core.Payload import Payload


class HashSchemaImpl(SchemaImpl):
    """
    In the Hashed schema, the data packets are all nameless objects.
    """
    def __init__(self, nc_id: NcId, schema: NcSchema, tree_options: ManifestTreeOptions):
        super().__init__()
        assert tree_options.schema_type == SchemaType.HASHED
        assert isinstance(schema, HashSchema)
        self._schema = schema
        self._nc_id = nc_id
        self._nc_def = NcDef(nc_id=nc_id, schema=schema)
        self._tree_options = tree_options

    def get_name(self, chunk_id) -> Optional[Name]:
        """
        HashSchema always uses nameless objects
        """
        return None

    def nc_id(self) -> NcId:
        return self._nc_id

    def locators(self) -> Optional[Locators]:
        return self._schema.locators()

    def chunk_data(self, data_input: BinaryIO, packet_output: PacketWriter) -> FileMetadata:
        chunk_metadata: List[ChunkMetadata] = []

        chunk_number = 0
        total_file_bytes = 0
        payload_size = self._calculate_nameless_data_payload_size()

        payload_value = data_input.read(payload_size)
        while len(payload_value) > 0:
            total_file_bytes += len(payload_value)
            packet = self._create_nameless_data_packet(payload_value)
            chunk_metadata.append(ChunkMetadata(chunk_number=chunk_number,
                                                payload_bytes=len(payload_value),
                                                content_object_hash=packet.content_object_hash()))
            packet_output.put(packet)
            # read next payload and loop
            payload_value = data_input.read(payload_size)

        return FileMetadata(total_bytes=total_file_bytes, chunk_metadata=chunk_metadata)

    def _calculate_nameless_data_payload_size(self):
        """
        Create a nameless object with empty payload and see how much space we have left.
        :return: payload size of a nameless data object
        """
        nameless = ContentObject.create_data(name=None,
                                             expiry_time=self._tree_options.data_expiry_time,
                                             payload=Payload([]))
        packet = Packet.create_content_object(body=nameless)
        if len(packet) >= self._tree_options.max_packet_size:
            raise ValueError("An empty nameless ContentObject is %r bytes, but max_size is only %r" %
                             (len(packet), self._tree_options.max_packet_size))

        payload_size = self._tree_options.max_packet_size - len(packet)
        return payload_size

    def _create_nameless_data_packet(self, payload_value):
        payload_tlv = Payload(payload_value)
        nameless = ContentObject.create_data(name=None,
                                             payload=payload_tlv,
                                             expiry_time=self._tree_options.data_expiry_time)
        packet = Packet.create_content_object(nameless)
        assert len(packet) <= self._tree_options.max_packet_size
        return packet
