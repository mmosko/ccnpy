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

from .HashGroupBuilderPair import HashGroupBuilderPair
from ..HashGroupBuilder import HashGroupBuilder
from ..ManifestFactory import ManifestFactory
from ..name_constructor.NameConstructorContext import NameConstructorContext
from ..name_constructor.SchemaImpl import SchemaImpl
from ..tlvs.StartSegmentId import StartSegmentId
from ...core.HashValue import HashValue


class ManifestSizeCalculator:
    """
    This class decides the maximuim number of pointers that can fit in a single manifest.  It does this by
    using the `max_packet_size` and filling in a Manifest to see how much space is left.

    The test manifest must have all possible fields that are used in a manifest filled in, so their space
    is accounted for.
    """

    # Used as the largest number of chunk id and manifest id and final chunk id.
    __MAX_MANIFEST_ID = 0xFFFFFF

    def __init__(self, max_packet_size: int, manifest_factory: ManifestFactory,
                                name_ctx: NameConstructorContext, total_bytes: int):
        self._max_packet_size = max_packet_size
        self._manifest_factory = manifest_factory
        self._name_ctx = name_ctx
        self._total_bytes = total_bytes

    def calculate_max_pointers(self) -> int:
        """
        Create a Manifest with the specified number of tree pointers and figure out how much space we have left
        out of self._max_size.  Then figure out how many data pointers we can fit in.

        We only put metadata and locators and things like that in the root manifest.

        :param max_packet_size: The maximum ccnpy.Packet size (bytes)
        :param manifest_factory: Factory used to create manifests
        :param total_bytes: The total file bytes.  We need to reserve big enough ints for leaf_size and subtree_size
        :return: The number of data points we can fit in a max_size nameless manifest (SHA256 HashValues)
        """
        # Assume 32-byte sha256 hashes
        hv = HashValue.create_sha256(32 * [0])
        hash_value_len = len(hv)
        packet = self._build_manifest_packet(1, hv)
        length = len(packet)
        if length >= self._max_packet_size:
            raise ValueError("An empty manifest packet is %r bytes and exceeds max_size %r" % (length, self._max_packet_size))

        slack = self._max_packet_size - length
        # +1 because we already have 1 hash in the manifest
        num_hashes = int(slack / hash_value_len) + 1

        # Now validate that it works
        packet = self._build_manifest_packet(num_hashes, hv)
        length = len(packet)
        if length > self._max_packet_size:
            raise ValueError(
                "A filled manifest packet is %r bytes with %r hashes, a hash is %r bytes, and exceeds max_size %r" %
                (length, num_hashes, hash_value_len, self._max_packet_size))

        #print("calculate_max_pointers = %r in length %r, actual length %r" % (num_hashes, max_packet_size, length))

        if num_hashes < 2:
            min_packet_size = len(packet) + hash_value_len
            raise ValueError("With max_packet_size %r there are %r hashes/manifest, must have at least 2."
                             "  Minimum packet_size is %r" % (self._max_packet_size, num_hashes, min_packet_size))
        return num_hashes

    def _build_manifest_packet(self, num_hashes, hv):
        # Arbitrary choise, we put n-1 into direct and 1 into indirect
        hgb = HashGroupBuilderPair(name_ctx=self._name_ctx, max_direct = num_hashes -1, max_indirect=1)

        for hv in (num_hashes -1) * [hv]:
            hgb.prepend_direct(hv)
        hgb.prepend_indirect(hv)
        if self._name_ctx.manifest_schema_impl.uses_name_id():
            indirect_start_segment_id = StartSegmentId(self.__MAX_MANIFEST_ID)
        else:
            indirect_start_segment_id = None

        if self._name_ctx.data_schema_impl.uses_name_id():
            direct_start_segment_id = StartSegmentId(SchemaImpl._MAX_CHUNK_ID)
        else:
            direct_start_segment_id = None

        # include_leaf_size and include_subtree_size might reserve too much space if we do not use those.
        hash_groups = hgb.hash_groups(include_leaf_size=True,
                                      include_subtree_size=True,
                                      indirect_start_segment_id=indirect_start_segment_id,
                                      direct_start_segment_id=direct_start_segment_id)

        packet = self._manifest_factory.build_packet(source=hash_groups,
                                               node_subtree_size=self._total_bytes)

        return packet

    def _build_single_hash_group(self, indirect_ptrs, direct_ptrs, nc_id):
        # We use total bytes for the subtree size and leaf size.  This might end up reserving one one more byte
        # than necessary if it overflows.
        hgb1 = HashGroupBuilder()
        for ptr in indirect_ptrs:
            hgb1.append_indirect(ptr, subtree_size=self._total_bytes)
        for ptr in direct_ptrs:
            hgb1.append_direct(ptr, leaf_size=self._total_bytes)

        hg1 = hgb1.hash_group(nc_id=nc_id,
                              include_leaf_size=self._manifest_factory.tree_options().add_group_leaf_size,
                              include_subtree_size=self._manifest_factory.tree_options().add_group_subtree_size)
        return hg1
