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
from typing import Optional

from ccnpy.core.Name import Name
from ccnpy.core.Packet import PacketWriter
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.SchemaImpl import SchemaImpl
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.NcId import NcId
from tests.MockReader import MockReader


class MockSchemaImpl(SchemaImpl):
    def __init__(self, max_chunk_size: int, tree_options: ManifestTreeOptions):

        super().__init__(nc_id=NcId(0), schema=None, tree_options=tree_options)
        self.max_chunk_size = max_chunk_size

    def locators(self) -> Optional[Locators]:
        pass

    def get_name(self, chunk_id) -> Optional[Name]:
        pass

    def nc_id(self) -> NcId:
        pass

    def _calculate_data_payload_size(self):
        return self.max_chunk_size

def create_file_chunks(packet_buffer: PacketWriter, data, max_chunk_size=1000):
    """
    We use a custom SchemaImpl so we can finely control the number of bytes per chunk
    """
    options = ManifestTreeOptions(max_packet_size=1500, name=None, schema_type=SchemaType.HASHED, signer=None)
    impl = MockSchemaImpl(max_chunk_size=max_chunk_size, tree_options=options)
    return impl.chunk_data(data_input=MockReader(data), packet_output=packet_buffer)

