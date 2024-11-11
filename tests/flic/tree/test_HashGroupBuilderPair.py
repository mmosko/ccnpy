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
from typing import Optional

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Name import Name
from ccnpy.flic.ManifestEncryptor import ManifestEncryptor
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.HashSchemaImpl import HashSchemaImpl
from ccnpy.flic.name_constructor.NameConstructorContext import NameConstructorContext
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.name_constructor.SegmentedSchemaImpl import SegmentedSchemaImpl
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.LeafSize import LeafSize
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import SegmentedSchema, HashSchema
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.StartSegmentId import StartSegmentId
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tree.HashGroupBuilderPair import HashGroupBuilderPair


class HashGroupBuilderPairTest(unittest.TestCase):

    @staticmethod
    def _create_options(max_packet_size: int, schema_type: SchemaType, encryptor: Optional[ManifestEncryptor] = None):
        return ManifestTreeOptions(max_packet_size=max_packet_size,
                                   name=None,
                                   schema_type=schema_type,
                                   signer=None,
                                   manifest_encryptor=encryptor)

    def _add_pointers(self, builders):
        builders.append_indirect(HashValue.create_sha256([7]), subtree_size=7)
        builders.append_indirect(HashValue.create_sha256([8]), subtree_size=6)
        for i in range(0, 7):
            builders.prepend_direct(HashValue.create_sha256([6 - i]), leaf_size=i)

    def test_one_builder_hashed(self):
        name=Name.from_uri('ccnx:/e')
        locators=Locators.from_name(name)
        nc_id = NcId(9)
        schema_impl = HashSchemaImpl(nc_id=nc_id, schema=HashSchema(locators=locators),
                                     tree_options=self._create_options(1500, schema_type=SchemaType.HASHED))
        name_ctx = NameConstructorContext(manifest_schema_impl=schema_impl, data_schema_impl=schema_impl)

        builders = HashGroupBuilderPair(name_ctx=name_ctx, max_direct=10, max_indirect=10)
        self.assertEqual(builders.direct_builder, builders.indirect_builder)

        self._add_pointers(builders)

        actual = builders.hash_groups(include_leaf_size=True, include_subtree_size=True)

        self.assertEqual(1, len(actual))
        actual_hg = actual[0]

        expected_hg = HashGroup(
            # leaf size = 0 + 1 + 2 + 3 + 4 + 5 + 6 = 21
            # subtree size = 21 + 7 + 6 = 34
            group_data=GroupData(subtree_size=SubtreeSize(34), leaf_size=LeafSize(21), nc_id=nc_id),
            pointers=Pointers([HashValue.create_sha256([i]) for i in range(0,9)])
        )

        self.assertEqual(expected_hg, actual_hg)

    def test_two_builder_segmented(self):
        manifest_prefix=Name.from_uri('ccnx:/g')
        data_prefix=Name.from_uri('ccnx:/h')
        options = self._create_options(1500, schema_type=SchemaType.SEGMENTED)
        name_ctx = NameConstructorContext(
            manifest_schema_impl=SegmentedSchemaImpl(nc_id=NcId(3), schema=SegmentedSchema(manifest_prefix), tree_options=options, use_chunk_id=False),
            data_schema_impl=SegmentedSchemaImpl(nc_id=NcId(4), schema=SegmentedSchema(data_prefix), tree_options=options, use_chunk_id=True)
        )

        builders = HashGroupBuilderPair(name_ctx=name_ctx, max_direct=10, max_indirect=10)
        self.assertNotEqual(builders.direct_builder, builders.indirect_builder)

        self._add_pointers(builders)

        actual = builders.hash_groups(include_leaf_size=True,
                                      include_subtree_size=True,
                                      direct_start_segment_id=StartSegmentId(1),
                                      indirect_start_segment_id=StartSegmentId(2))

        self.assertEqual(2, len(actual))
        actual_direct = actual[0]
        expected_direct = HashGroup(
            # leaf size = 0 + 1 + 2 + 3 + 4 + 5 + 6 = 21
            # subtree size = 21
            group_data=GroupData(subtree_size=SubtreeSize(21),
                                 leaf_size=LeafSize(21),
                                 start_segment_id=StartSegmentId(1),
                                 nc_id=name_ctx.data_schema_impl.nc_id()),
            pointers=Pointers([HashValue.create_sha256([i]) for i in range(0,7)])
        )
        self.assertEqual(expected_direct, actual_direct)

        actual_indirect = actual[1]
        expected_indirect = HashGroup(
            # leaf size = 0
            # subtree size = 7 + 6 = 13
            group_data=GroupData(subtree_size=SubtreeSize(13),
                                 leaf_size=LeafSize(0),
                                 start_segment_id=StartSegmentId(2),
                                 nc_id=name_ctx.manifest_schema_impl.nc_id()),
            pointers=Pointers([HashValue.create_sha256([i]) for i in range(7,9)])
        )
        self.assertEqual(expected_indirect, actual_indirect)
