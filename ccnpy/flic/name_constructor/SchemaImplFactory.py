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
from ccnpy.flic.tlvs.NcSchema import HashSchema, NcSchema, PrefixSchema, SegmentedSchema
from .PrefixSchemaImpl import PrefixSchemaImpl
from .SchemaType import SchemaType
from .SegmentedSchemaImpl import SegmentedSchemaImpl
from ..ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.HashSchemaImpl import HashSchemaImpl
from ..tlvs.Locators import Locators
from ...core.Name import Name


class SchemaImplFactory:
    #
    # @staticmethod
    # def create(nc_id: NcId, schema: NcSchema, tree_options: ManifestTreeOptions):
    #     if isinstance(schema, HashSchema):
    #         return HashSchemaImpl(nc_id=nc_id, schema=schema, tree_options=tree_options)
    #
    #     raise ValueError(f"Unsupported SchemaType: {tree_options.schema_type}")

    _next_nc_id = 1

    @classmethod
    def reset_nc_id(cls):
        """Used in unit tests to reset to known state"""
        cls._next_nc_id = 1

    @classmethod
    def _get_and_increment_ncid(cls):
        next_nc_id = cls._next_nc_id
        cls._next_nc_id += 1
        return next_nc_id

    @classmethod
    def create(cls, tree_options: ManifestTreeOptions, locators: Optional[Locators] = None, name: Optional[Name] = None):
        """
        Creates a schema with the next available NCID and its implementation.
        """
        nc_id = NcId(cls._get_and_increment_ncid())
        if tree_options.schema_type == SchemaType.HASHED:
            return HashSchemaImpl(nc_id=nc_id, schema=HashSchema(locators=locators), tree_options=tree_options)

        if tree_options.schema_type == SchemaType.PREFIX:
            return PrefixSchemaImpl(nc_id=nc_id, schema=PrefixSchema(name=name), tree_options=tree_options)

        if tree_options.schema_type == SchemaType.SEGMENTED:
            return SegmentedSchemaImpl(nc_id=nc_id, schema=SegmentedSchema(name=name), tree_options=tree_options)

        raise ValueError(f"Unsupported SchemaType: {tree_options.schema_type}")
