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

from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import SegmentedSchema
from ccnpy.flic.name_constructor.SchemaImpl import SchemaImpl
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.core.Name import Name, NameComponent


class SegmentedSchemaImpl(SchemaImpl):
    """
    The segmented schema will append a chunk number to the name.  CCNx does not use locators with
    SegmentedSchema.
    """

    def __init__(self, nc_id: NcId, schema: SegmentedSchema, tree_options: ManifestTreeOptions):
        """
        The `name` is what we will use for the name constructor.  You must derive this name from the
        `tree_options` before calling this.  See `NameConstructorContext` for examples.

        :param use_chunk_id: If true, uses ChunkId and FinalChunkId fields.  if false, uses only manifest_id in name.
        """
        super().__init__(nc_id=nc_id, schema=schema, tree_options=tree_options)
        assert isinstance(self._schema, SegmentedSchema)
        if schema.count() > 0:
            raise ValueError("CCNx does not support locators for SegmentedSchema")
        self._name = schema.name()
        self._suffix_type = schema.suffix_type()

    def __repr__(self):
        return f'SegmentedImpl(name={self._name}, nc_id={self._nc_id}, schema={self._schema})'

    def get_name(self, suffix_id) -> Optional[Name]:
        """
        HashSchema always uses nameless objects
        """
        return self._name.append(self._suffix_type.create_name_component(suffix_id))

    def nc_id(self) -> NcId:
        return self._nc_id

    def locators(self) -> Optional[Locators]:
        return None

    @staticmethod
    def uses_name_id() -> bool:
        return True

    def uses_final_chunk_id(self) -> bool:
        return self._suffix_type.value() == NameComponent.chunk_id_type()
