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


import unittest

from ccnpy.core.Name import Name
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.NameConstructorContext import NameConstructorContext
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.Locators import Locators


class NameConstructorContextTest(unittest.TestCase):

    def setUp(self):
        self.root_name = Name.from_uri('ccnx:/a')
        self.manifest_name = Name.from_uri('ccnx:/b')
        self.data_name = Name.from_uri('ccnx:/c')

    def test_hashed_single_name(self):
        options = ManifestTreeOptions(name=self.root_name, schema_type=SchemaType.HASHED, signer=None)
        ctx = NameConstructorContext.create(options)
        # There should be the same ncid in both impls.
        self.assertEqual(ctx.manifest_schema_impl, ctx.data_schema_impl)

        # They should both use 'name'
        expected_name = self.root_name
        self.assertEqual(expected_name, ctx.manifest_schema_impl.locators()[0].name())

    def test_hashed_manifest_locator(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.HASHED,
                                      manifest_locators=Locators.from_name(self.manifest_name),
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(Locators.from_name(self.manifest_name), ctx.manifest_schema_impl.locators())
        self.assertEqual(Locators.from_name(self.root_name), ctx.data_schema_impl.locators())

    def test_hashed_data_locator(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.HASHED,
                                      data_locators=Locators.from_name(self.data_name),
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(Locators.from_name(self.root_name), ctx.manifest_schema_impl.locators())
        self.assertEqual(Locators.from_name(self.data_name), ctx.data_schema_impl.locators())

    def test_hashed_both_locator(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.HASHED,
                                      manifest_locators=Locators.from_name(self.manifest_name),
                                      data_locators=Locators.from_name(self.data_name),
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(Locators.from_name(self.manifest_name), ctx.manifest_schema_impl.locators())
        self.assertEqual(Locators.from_name(self.data_name), ctx.data_schema_impl.locators())

# ====

    def test_prefix_single_name(self):
        options = ManifestTreeOptions(name=self.root_name, schema_type=SchemaType.PREFIX, signer=None)
        ctx = NameConstructorContext.create(options)
        # There should be the same ncid in both impls.
        self.assertEqual(ctx.manifest_schema_impl, ctx.data_schema_impl)

        # They should both use 'name'.  prefix will not append a chunk id
        self.assertEqual(self.root_name, ctx.manifest_schema_impl.get_name(0))
        self.assertEqual(self.root_name, ctx.data_schema_impl.get_name(0))

    def test_prefix_manifest_prefix(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.PREFIX,
                                      manifest_prefix=self.manifest_name,
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(self.manifest_name, ctx.manifest_schema_impl.get_name(1))
        self.assertEqual(self.root_name, ctx.data_schema_impl.get_name(2))

    def test_prefix_data_prefix(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.PREFIX,
                                      data_prefix=self.data_name,
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(self.root_name, ctx.manifest_schema_impl.get_name(1))
        self.assertEqual(self.data_name, ctx.data_schema_impl.get_name(2))

    def test_prefix_both_prefix(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.PREFIX,
                                      manifest_prefix=self.manifest_name,
                                      data_prefix=self.data_name,
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(self.manifest_name, ctx.manifest_schema_impl.get_name(1))
        self.assertEqual(self.data_name, ctx.data_schema_impl.get_name(2))

# ===

    def test_segmented_single_name(self):
        options = ManifestTreeOptions(name=self.root_name, schema_type=SchemaType.SEGMENTED, signer=None)

        # Segmented requires distinct manifest and data prefixes.
        with self.assertRaises(ValueError):
            NameConstructorContext.create(options)


    def test_segmented_manifest_prefix(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.SEGMENTED,
                                      manifest_prefix=self.manifest_name,
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(self.manifest_name.append_manifest_id(1), ctx.manifest_schema_impl.get_name(1))
        self.assertEqual(self.root_name.append_chunk_id(2), ctx.data_schema_impl.get_name(2))

    def test_segmented_data_prefix(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.SEGMENTED,
                                      data_prefix=self.data_name,
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(self.root_name.append_manifest_id(1), ctx.manifest_schema_impl.get_name(1))
        self.assertEqual(self.data_name.append_chunk_id(2), ctx.data_schema_impl.get_name(2))

    def test_segmented_both_prefix(self):
        options = ManifestTreeOptions(name=self.root_name,
                                      schema_type=SchemaType.SEGMENTED,
                                      manifest_prefix=self.manifest_name,
                                      data_prefix=self.data_name,
                                      signer=None)
        ctx = NameConstructorContext.create(options)

        # There should be different NcIDs
        self.assertNotEqual(ctx.manifest_schema_impl.nc_id(), ctx.data_schema_impl.nc_id())

        self.assertEqual(self.manifest_name.append_manifest_id(1), ctx.manifest_schema_impl.get_name(1))
        self.assertEqual(self.data_name.append_chunk_id(2), ctx.data_schema_impl.get_name(2))
