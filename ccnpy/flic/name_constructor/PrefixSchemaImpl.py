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
from ccnpy.flic.tlvs.NcSchema import PrefixSchema
from ccnpy.flic.name_constructor.SchemaImpl import SchemaImpl
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.core.Name import Name


class PrefixSchemaImpl(SchemaImpl):
    """
    In the Hashed schema, the data packets are all nameless objects.
    """

    def __init__(self, nc_id: NcId, schema: PrefixSchema, tree_options: ManifestTreeOptions):
        super().__init__(nc_id=nc_id, schema=schema, tree_options=tree_options)
        assert tree_options.schema_type == SchemaType.PREFIX
        assert isinstance(self._schema, PrefixSchema)
        if schema.count() > 0:
            raise ValueError("CCNx does not support locators for PrefixSchema")
        self._name = schema.name()

    def get_name(self, chunk_id) -> Optional[Name]:
        """
        PrefixSchema always uses the same name
        """
        return self._name

    def nc_id(self) -> NcId:
        return self._nc_id

    def locators(self) -> Optional[Locators]:
        return None

