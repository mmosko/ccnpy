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

from abc import ABC, abstractmethod
from typing import Optional, List

from .FileMetadata import FileMetadata, ChunkMetadata
from ccnpy.flic.tlvs.NcDef import NcDef
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import NcSchema
from ccnpy.flic.tlvs.Locators import Locators
from ..ManifestTreeOptions import ManifestTreeOptions
from ...core.ContentObject import ContentObject
from ...core.FinalChunkId import FinalChunkId
from ...core.Name import Name
from ...core.Packet import PacketWriter, Packet
from ...core.Payload import Payload


class SchemaImpl(ABC):
    """
    The NcSchema-derived classes define the Manifest TLVs for different schemas.  The `SchemaImpl` derived
    classes implement the schemas.
    """
    # This is to reserve up to 3 bytes for the chunk ID.  See the to-do below.
    _MAX_CHUNK_ID = 0xFFFFFF

    def __init__(self, nc_id: NcId, schema: NcSchema, tree_options: ManifestTreeOptions):
        self._next_chunk_id = 0
        self._schema = schema
        self._nc_id = nc_id
        self._nc_def = NcDef(nc_id=nc_id, schema=schema)
        self._tree_options = tree_options

    def _get_and_increment_next_chunk_id(self) -> int:
        next_chunk_id = self._next_chunk_id
        self._next_chunk_id += 1
        return next_chunk_id

    def get_next_name(self) -> Optional[Name]:
        """
        Returns the name of the next object, which maybe None for hash schema.  This metnod increments an internal
        counter to track the generated names.
        """
        next_chunk_id = self._get_and_increment_next_chunk_id()
        return self.get_name(chunk_id=next_chunk_id)

    def nc_id(self) -> NcId:
        return self._nc_id

    def nc_def(self) -> NcDef:
        return self._nc_def

    @abstractmethod
    def locators(self) -> Optional[Locators]:
        """The locators associated with this schema, which may be None"""
        pass

    @abstractmethod
    def get_name(self, chunk_id) -> Optional[Name]:
        """
        Returns the CCNx name of the object at `chunk_id` offset.
        """
        pass

    @staticmethod
    def uses_name_id() -> bool:
        """Does this schema include an ID in a name component?"""
        return False

    @staticmethod
    def uses_final_chunk_id() -> bool:
        """Does this schema include FinalChunkId field in the content object?"""
        return False


    def chunk_data(self, data_input, packet_output: PacketWriter) -> FileMetadata:
        """
        Chunks the data using the given name schema.  Multiple calls to this method will
        result in consecutive `chunk_id`, as the NcSchema keeps incrementing the sequence number.
        """
        chunk_metadata: List[ChunkMetadata] = []

        total_file_bytes = 0
        payload_size = self._calculate_data_payload_size()

        payload_value = data_input.read(payload_size)
        while len(payload_value) > 0:
            total_file_bytes += len(payload_value)
            chunk_id = self._get_and_increment_next_chunk_id()
            if chunk_id > self._MAX_CHUNK_ID:
                raise ValueError(f"Implementation is limited to {self._MAX_CHUNK_ID} chunks.  Bytes processed so far: {total_file_bytes}")

            chunk_name = self.get_name(chunk_id)

            # We read the next part of the file to see if we are at the end.  If so, we can set the
            # final chunk id in the content object.
            next_payload_value = data_input.read(payload_size)
            if self.uses_final_chunk_id() and len(next_payload_value) == 0:
                fcid = FinalChunkId(chunk_id)
            else:
                fcid = None

            packet = self._create_data_packet(name=chunk_name, payload_value=payload_value, fcid=fcid)
            chunk_metadata.append(ChunkMetadata(chunk_number=chunk_id,
                                                payload_bytes=len(payload_value),
                                                content_object_hash=packet.content_object_hash()))
            packet_output.put(packet)

            # read next payload and loop
            payload_value = next_payload_value

        return FileMetadata(total_bytes=total_file_bytes, chunk_metadata=chunk_metadata)

    def _calculate_data_payload_size(self):
        """
        Create a nameless object with empty payload and see how much space we have left.
        :return: payload size of a nameless data object
        """

        # TODO: We need to loop on this to make sure that the size of the name can fit the number
        # of data chunks.  Right now, we just reserve 3 bytes.  Same for final chunk id.
        if self.uses_name_id():
            fcid = FinalChunkId(self._MAX_CHUNK_ID)
        else:
            fcid = None

        named = ContentObject.create_data(name=self.get_name(self._MAX_CHUNK_ID),
                                          expiry_time=self._tree_options.data_expiry_time,
                                          payload=Payload([]),
                                          final_chunk_id=fcid)

        packet = Packet.create_content_object(body=named)
        if len(packet) >= self._tree_options.max_packet_size:
            raise ValueError("An empty named ContentObject is %r bytes, but max_size is only %r" %
                             (len(packet), self._tree_options.max_packet_size))

        payload_size = self._tree_options.max_packet_size - len(packet)
        return payload_size

    def _create_data_packet(self, name: Name, payload_value, fcid: Optional[FinalChunkId]):
        payload_tlv = Payload(payload_value)
        nameless = ContentObject.create_data(name=name,
                                             payload=payload_tlv,
                                             expiry_time=self._tree_options.data_expiry_time,
                                             final_chunk_id=fcid)
        packet = Packet.create_content_object(nameless)
        if len(packet) > self._tree_options.max_packet_size:
            raise ValueError(f'The final packet length {len(packet)} > max packet size {self._tree_options.max_packet_size}')
        return packet
