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
from dataclasses import dataclass
from typing import List, Dict

from .SchemaImpl import SchemaImpl
from .SchemaImplFactory import SchemaImplFactory
from .SchemaType import SchemaType
from ..ManifestTreeOptions import ManifestTreeOptions
from ..tlvs.Locators import Locators
from ..tlvs.NcDef import NcDef
from ...core.Name import Name


@dataclass
class NameConstructorContext:
    """
    This is the top-level name constructor object that is used by `ManifestTree` and related classes.  it defines the
    name constructors used in the manifest and provides the needed behavior to generate names and chunk numbers.
    """
    manifest_schema_impl: SchemaImpl
    data_schema_impl: SchemaImpl

    def hash_group_count(self):
        if self.manifest_schema_impl == self.data_schema_impl:
            return 1
        else:
            return 2

    def nc_def(self) -> List[NcDef]:
        """Returns one or two NcDefs, depeding on if they are unique"""
        if self.manifest_schema_impl == self.data_schema_impl:
            return [self.manifest_schema_impl.nc_def()]
        else:
            return [self.manifest_schema_impl.nc_def(), self.data_schema_impl.nc_def()]

    @classmethod
    def create(cls, tree_options: ManifestTreeOptions):
        if tree_options.schema_type == SchemaType.HASHED:
            return cls._create_hashed(tree_options)

        if tree_options.schema_type == SchemaType.SEGMENTED:
            return cls._create_segmented(tree_options)

        if tree_options.schema_type == SchemaType.PREFIX:
            return cls._create_prefix(tree_options)

    @classmethod
    def _create_hashed(cls, tree_options: ManifestTreeOptions):
        """
        Nameless objects require a locator.  The default is to use `tree_options.root_name` as the locator for all
        nameless objects.  If `tree_options.manifest_locator` is given, then it is used as the manifest locator instead
        of the root name.  If `tree_options.data_locator` is given, then it is used for the data locator instead of
        the root name.

        If the manifest and data locators are different, then two hash groups are used.
        """
        root_locator = Locators.from_name(tree_options.name)
        manifest_locator = root_locator if tree_options.manifest_locators is None else tree_options.manifest_locators
        data_locator = root_locator if tree_options.data_locators is None else tree_options.data_locators

        if manifest_locator == data_locator:
            # one hash group
            schema_impl = SchemaImplFactory.create(locators=manifest_locator, tree_options=tree_options)
            return cls(manifest_schema_impl=schema_impl, data_schema_impl=schema_impl)
        else:
            # two hash groups
            return cls(manifest_schema_impl=SchemaImplFactory.create(locators=manifest_locator, tree_options=tree_options),
                       data_schema_impl=SchemaImplFactory.create(locators=data_locator, tree_options=tree_options))

    @classmethod
    def _create_named(cls, tree_options: ManifestTreeOptions, manifest_prefix: Name, data_prefix: Name):
        """
        Prefix and segmented have the same structure, but different rules about which names could be the same
        as other names.
        """
        if manifest_prefix == data_prefix:
            # one hash group, only possible for PREFIX schema
            schema_impl = SchemaImplFactory.create(name=manifest_prefix,
                                                   locators=None,
                                                   tree_options=tree_options)
            return cls(manifest_schema_impl=schema_impl, data_schema_impl=schema_impl)
        else:
            # two hash groups
            return cls(manifest_schema_impl=SchemaImplFactory.create(name=manifest_prefix,
                                                                     locators=None,
                                                                     tree_options=tree_options,
                                                                     for_manifest=True),
                       data_schema_impl=SchemaImplFactory.create(name=data_prefix,
                                                                 locators=None,
                                                                 tree_options=tree_options,
                                                                 for_manifest=False))

    @classmethod
    def _create_prefix(cls, tree_options: ManifestTreeOptions):
        root_name = tree_options.name
        manifest_prefix = root_name if tree_options.manifest_prefix is None else tree_options.manifest_prefix
        data_prefix = root_name if tree_options.data_prefix is None else tree_options.data_prefix
        return cls._create_named(tree_options=tree_options, manifest_prefix=manifest_prefix, data_prefix=data_prefix)

    @classmethod
    def _create_segmented(cls, tree_options: ManifestTreeOptions):
        root_name = tree_options.name
        if root_name is None:
            raise ValueError('For SegmentedSchema, the --name must not be None')
        manifest_prefix = root_name if tree_options.manifest_prefix is None else tree_options.manifest_prefix
        data_prefix = root_name if tree_options.data_prefix is None else tree_options.data_prefix
        if manifest_prefix == data_prefix:
            raise ValueError(f'Manifest prefix {manifest_prefix} must be distinct from data prefix {data_prefix}')
        return cls._create_named(tree_options=tree_options, manifest_prefix=manifest_prefix, data_prefix=data_prefix)

    def export_schemas(self) -> Dict[int, SchemaImpl]:
        """This is the structure used by `Traversal.NameConstructorCache`"""
        d = {self.manifest_schema_impl.nc_id().id(): self.manifest_schema_impl}
        if self.hash_group_count() == 2:
            d[self.data_schema_impl.nc_id().id()] = self.data_schema_impl
        return d
