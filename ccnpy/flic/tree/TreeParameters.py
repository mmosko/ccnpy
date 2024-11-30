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

from .ManifestSizeCalculator import ManifestSizeCalculator
from .OptimizerResult import OptimizerResult
from .TreeOptimizer import TreeOptimizer
from ..ManifestFactory import ManifestFactory
from ..name_constructor.FileMetadata import FileMetadata
from ..name_constructor.NameConstructorContext import NameConstructorContext


class TreeParameters:
    """
    These are the detailed tree parameters that direct how to build a manifest tree.  It is calculated based
    on `ManifestTreeOptions.max_packet_size` and `ManifestTreeOptions.max_tree_degree` and the size of the
    user data, which are user-input options.

    Usually, one calls `create_optimized_tree` to calculate these parameters.
    """

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

        num_pointers_per_node = ManifestSizeCalculator(max_packet_size=max_packet_size,
                                                            manifest_factory=manifest_factory,
                                                            name_ctx=name_ctx,
                                                            total_bytes=file_metadata.total_bytes).calculate_max_pointers()

        if num_pointers_per_node < 2:
            # TODO: This is not entirely true.  If the app data is only 1 chunk, it could work.
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

    @staticmethod
    def _optimize_tree(total_direct_nodes:int , num_pointers_per_node: int) -> OptimizerResult:
        to = TreeOptimizer(num_direct_nodes=total_direct_nodes,
                           num_pointers=num_pointers_per_node)

        # There are a few possible outputs from the tree optimizer.  In general, we use
        # this one, as it picks the tree that fits the data well (minimizes waste), and then
        # from those picks one with minimum height.
        #return to.minimize_k()
        return to.minimize_k_min_waste()
        # return to.minimize_waste_min_height()
