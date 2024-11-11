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
import math
from typing import Optional

from .HashGroupBuilderPair import HashGroupBuilderPair
from .OptimizerResult import OptimizerResult
from .TreeOptimizer import TreeOptimizer
from ..HashGroupBuilder import HashGroupBuilder
from ..ManifestFactory import ManifestFactory
from ccnpy.flic.tlvs.Pointers import Pointers
from ..name_constructor.FileMetadata import FileMetadata
from ..name_constructor.NameConstructorContext import NameConstructorContext
from ..name_constructor.SchemaImpl import SchemaImpl
from ..tlvs.StartSegmentId import StartSegmentId
from ...core.HashValue import HashValue


class TreeParameters:
    """
    These are the detailed tree parameters that direct how to build a manifest tree.  It is calculated based
    on `ManifestTreeOptions.max_packet_size` and `ManifestTreeOptions.max_tree_degree` and the size of the
    user data, which are user-input options.

    Usually, one calls `create_optimized_tree` to calculate these parameters.
    """
    __MAX_MANIFEST_ID = 0xFFFFFF

    @classmethod
    def create_optimized_tree(cls,
                              file_metadata: FileMetadata,
                              manifest_factory: ManifestFactory,
                              name_ctx: NameConstructorContext):
        """
        :param file_metadata: Info about each file chunk.
        :param manifest_factory: If using non-standard tree options, pass your own factory to get correct sizes.
        :param name_ctx: The name constructor context, so we can reserve the needed space for names
        :return:
        """
        max_packet_size = manifest_factory.tree_options().max_packet_size
        max_tree_degree = manifest_factory.tree_options().max_tree_degree

        num_pointers_per_node = cls._calculate_max_pointers(max_packet_size=max_packet_size,
                                                            manifest_factory=manifest_factory,
                                                            name_ctx=name_ctx,
                                                            total_bytes=file_metadata.total_bytes)

        if num_pointers_per_node < 2:
            raise ValueError("With a max_packet_size of %r there is only %r pointers per node, must have at least 2" %
                             (max_packet_size, num_pointers_per_node))

        if max_tree_degree is not None:
            num_pointers_per_node = min(num_pointers_per_node, max_tree_degree)

        solution = cls._optimize_tree(total_direct_nodes=len(file_metadata), num_pointers_per_node=num_pointers_per_node)
        return cls(file_metadata=file_metadata, max_packet_size=max_packet_size, solution=solution)

    def __init__(self, file_metadata: FileMetadata, max_packet_size: int, solution: OptimizerResult):
        """

        :param file_chunks: A Pointers
        :param max_packet_size:
        """
        self._max_size = max_packet_size
        self._total_direct_nodes = len(file_metadata)
        self._num_pointers_per_node = solution.indirect_per_node() + solution.direct_per_node()
        self._solution = solution

    def __repr__(self):
        return "{TreeParams pkt_size=%r, solution=%r}" % (self._max_size, self._solution)

    def max_size(self):
        """
        Maximum size for a ContentObject
        :return:
        """
        return self._max_size

    def internal_direct_per_node(self):
        """
        The number of direct pointers on each internal node.
        :return:
        """
        return self._solution.direct_per_node()

    def internal_indirect_per_node(self):
        """
        The number of indirect pointers on each internal node.
        :return:s
        """
        return self._solution.indirect_per_node()

    def total_direct_nodes(self):
        """
        The number of direct nodes -- nameless ContentObjects with application payload
        :return:
        """
        return self._total_direct_nodes

    def num_pointers_per_node(self):
        """
        The number of pointers (direct + indirect) that fit in a nameless manifest node.
        :return:
        """
        return self._num_pointers_per_node

    def total_nodes(self):
        """
        The total number of manifest nodes (internal plus leaf)
        """
        return self._solution.total_nodes()

    def tree_height(self) -> int:
        """
        The total tree height, including leaf nodes.
        """
        return self._solution.tree_height()

    @classmethod
    def _build_single_hash_group(cls, manifest_factory, indirect_ptrs, direct_ptrs, nc_id, total_bytes):
        # We use total bytes for the subtree size and leaf size.  This might end up reserving one one more byte
        # than necessary if it overflows.
        hgb1 = HashGroupBuilder()
        for ptr in indirect_ptrs:
            hgb1.append_indirect(ptr, subtree_size=total_bytes)
        for ptr in direct_ptrs:
            hgb1.append_direct(ptr, leaf_size=total_bytes)

        hg1 = hgb1.hash_group(nc_id=nc_id,
                              include_leaf_size=manifest_factory.tree_options().add_group_leaf_size,
                              include_subtree_size=manifest_factory.tree_options().add_group_subtree_size)
        return hg1

    @classmethod
    def _build_manifest_packet(cls, manifest_factory, num_hashes, hv, name_ctx, total_bytes):
        # Arbitrary choise, we put n-1 into direct and 1 into indirect
        hgb = HashGroupBuilderPair(name_ctx=name_ctx, max_direct = num_hashes -1, max_indirect=1)

        for hv in (num_hashes -1) * [hv]:
            hgb.prepend_direct(hv)
        hgb.prepend_indirect(hv)
        if name_ctx.manifest_schema_impl.uses_name_id():
            indirect_start_segment_id = StartSegmentId(cls.__MAX_MANIFEST_ID)
        else:
            indirect_start_segment_id = None

        if name_ctx.data_schema_impl.uses_name_id():
            direct_start_segment_id = StartSegmentId(SchemaImpl._MAX_CHUNK_ID)
        else:
            direct_start_segment_id = None

        # include_leaf_size and include_subtree_size might reserve too much space if we do not use those.
        hash_groups = hgb.hash_groups(include_leaf_size=True,
                                      include_subtree_size=True,
                                      indirect_start_segment_id=indirect_start_segment_id,
                                      direct_start_segment_id=direct_start_segment_id)

        packet = manifest_factory.build_packet(source=hash_groups, node_subtree_size=total_bytes)

        return packet

    @classmethod
    def _calculate_max_pointers(cls, max_packet_size: int, manifest_factory: ManifestFactory,
                                name_ctx: NameConstructorContext, total_bytes: int):
        """
        Create a Manifest with the specified number of tree pointers and figure out how much space we have left
        out of self._max_size.  Then figure out how many data pointers we can fit in.

        We only put metadata and locators and things like that in the root manifest.

        :param max_packet_size: The maximum ccnpy.Packet size (bytes)
        :param manifest_factory: Factory used to create manifests
        :param total_bytes: The total file bytes.  We need to reserve big enough ints for leaf_size and subtree_size
        :return: The number of data points we can fit in a max_size nameless manifest
        """
        # Assume 32-byte sha256 hashes
        hv = HashValue.create_sha256(32 * [0])
        hash_value_len = len(hv)
        packet = cls._build_manifest_packet(manifest_factory, 1, hv, name_ctx, total_bytes)
        length = len(packet)
        if length >= max_packet_size:
            raise ValueError("An empty manifest packet is %r bytes and exceeds max_size %r" % (length, max_packet_size))

        slack = max_packet_size - length
        # +1 because we already have 1 hash in the manifest
        num_hashes = int(slack / hash_value_len) + 1

        # Now validate that it works
        packet = cls._build_manifest_packet(manifest_factory, num_hashes, hv, name_ctx, total_bytes)
        length = len(packet)
        if length > max_packet_size:
            raise ValueError(
                "A filled manifest packet is %r bytes with %r hashes, a hash is %r bytes, and exceeds max_size %r" %
                (length, num_hashes, hash_value_len, max_packet_size))

        #print("calculate_max_pointers = %r in length %r, actual length %r" % (num_hashes, max_packet_size, length))

        if num_hashes < 2:
            min_packet_size = len(packet) + hash_value_len
            raise ValueError("With max_packet_size %r there are %r hashes/manifest, must have at least 2."
                             "  Minimum packet_size is %r" % (max_packet_size, num_hashes, min_packet_size))
        return num_hashes

    @staticmethod
    def _optimize_tree(total_direct_nodes:int , num_pointers_per_node: int) -> OptimizerResult:
        to = TreeOptimizer(num_direct_nodes=total_direct_nodes,
                           num_pointers=num_pointers_per_node)
        solutions = to.minimize_waste()
        # the results are sorted by m (number of indirect pointers per node), so pick something in the middle
        middle_solution = solutions[int(len(solutions) / 2)]
        return middle_solution
