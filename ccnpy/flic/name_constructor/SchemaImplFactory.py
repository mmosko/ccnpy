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
from .NcDef import NcDef
from .NcId import NcId
from .NcSchema import HashSchema, NcSchema
from ..ManifestTreeOptions import ManifestTreeOptions
from ..name_constructor.SchemaType import SchemaType
from ..name_constructor.impl.HashSchemaImpl import HashSchemaImpl


class SchemaImplFactory:

    @staticmethod
    def create(nc_id: NcId, schema: NcSchema, tree_options: ManifestTreeOptions):
        if isinstance(schema, HashSchema):
            return HashSchemaImpl(nc_id=nc_id, schema=schema, tree_options=tree_options)

        raise ValueError(f"Unsupported SchemaType: {tree_options.schema_type}")
