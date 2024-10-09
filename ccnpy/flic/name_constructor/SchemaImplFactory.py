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

from ..ManifestTreeOptions import ManifestTreeOptions
from ..name_constructor.SchemaType import SchemaType
from ..name_constructor.impl.HashSchemaImpl import HashSchemaImpl


class SchemaImplFactory:

    @staticmethod
    def create(tree_options: ManifestTreeOptions):
        if tree_options.schema_type == SchemaType.HASHED:
            return HashSchemaImpl(tree_options=tree_options)

        raise ValueError(f"Unsupported SchemaType: {tree_options.schema_type}")
