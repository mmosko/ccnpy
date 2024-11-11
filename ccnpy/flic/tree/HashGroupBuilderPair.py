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
from typing import Optional, List

from ccnpy.core.HashValue import HashValue
from ccnpy.flic.HashGroupBuilder import HashGroupBuilder
from ccnpy.flic.name_constructor.NameConstructorContext import NameConstructorContext
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.StartSegmentId import StartSegmentId


class HashGroupBuilderPair:
    """
    Uses one or two has group builders, as needed.  Provides a facade of HashGroupBuilder, so the usage
    is just like HashGroupBuilder.
    """
    DEBUG = False

    def __init__(self, name_ctx: NameConstructorContext, max_direct: int, max_indirect: int):
        self._name_ctx = name_ctx
        if name_ctx.hash_group_count() == 1:
            self.direct_builder = HashGroupBuilder(max_direct=max_direct, max_indirect=max_indirect)
            self.indirect_builder = self.direct_builder
        elif name_ctx.hash_group_count() == 2:
            self.direct_builder = HashGroupBuilder(max_direct=max_direct, max_indirect=0)
            self.indirect_builder = HashGroupBuilder(max_direct=0, max_indirect=max_indirect)
        else:
            raise RuntimeError('HashGroupBuilderPair can only accommodate 1 or 2 hash groups')

    def prepend_direct(self, hash_value: HashValue, leaf_size: Optional[int] = None):
        self.direct_builder.prepend_direct(hash_value=hash_value, leaf_size=leaf_size)

    def append_indirect(self, hash_value: HashValue, subtree_size: Optional[int] = None):
        self.indirect_builder.append_indirect(hash_value=hash_value, subtree_size=subtree_size)

    def is_direct_full(self):
        return self.direct_builder.is_direct_full()

    def is_indirect_full(self):
        return self.indirect_builder.is_indirect_full()

    def prepend_indirect(self, hash_value: HashValue, subtree_size: Optional[int] = None):
        self.indirect_builder.prepend_indirect(hash_value=hash_value, subtree_size=subtree_size)

    def direct_size(self):
        return self.direct_builder.direct_size()

    def indirect_size(self):
        return self.indirect_builder.indirect_size()

    def hash_groups(self, include_leaf_size: bool, include_subtree_size: bool,
                    direct_start_segment_id: Optional[StartSegmentId]=None,
                    indirect_start_segment_id: Optional[StartSegmentId]=None) -> List[HashGroup]:
        if self.DEBUG:
            print(f"build hash group (direct_seg_id={direct_start_segment_id}, ind_seg_id={indirect_start_segment_id})")
        if self._name_ctx.hash_group_count() == 1:
            # we cannot have segmented names if there's only one builder
            assert direct_start_segment_id is None
            assert indirect_start_segment_id is None
            return [self.direct_builder.hash_group(include_leaf_size=include_leaf_size,
                                                   include_subtree_size=include_subtree_size,
                                                   nc_id=self._name_ctx.manifest_schema_impl.nc_id())]
        else:
            assert direct_start_segment_id is None or isinstance(direct_start_segment_id, StartSegmentId)
            assert indirect_start_segment_id is None or isinstance(indirect_start_segment_id, StartSegmentId)
            # for proper traversal order, direct must come before indirect.  In preorder, we visit the current
            # node before the children.
            return [
                self.direct_builder.hash_group(include_leaf_size=include_leaf_size,
                                               include_subtree_size=include_subtree_size,
                                               nc_id=self._name_ctx.data_schema_impl.nc_id(),
                                               start_segment_id=direct_start_segment_id),
                self.indirect_builder.hash_group(include_leaf_size=include_leaf_size,
                                                 include_subtree_size=include_subtree_size,
                                                 nc_id=self._name_ctx.manifest_schema_impl.nc_id(),
                                                 start_segment_id=indirect_start_segment_id)
            ]
