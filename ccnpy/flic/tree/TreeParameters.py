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
from .TreeOptimizer import TreeOptimizer
from ..ManifestFactory import ManifestFactory
from ..Pointers import Pointers
from ...core.HashValue import HashValue


class TreeParameters:
    @classmethod
    def create_optimized_tree(cls, file_chunks, max_packet_size, max_tree_degree=None, manifest_factory=None):
        """
        :param file_chunks: A Pointers object listing all the file hashes in order
        :param max_packet_size: Maximum byte length of a CCNx Packet
        :param max_tree_degree: Maximum degree, limited by packet size.  None means only limited by packet size.
        :param manifest_factory: If using non-standard tree options, pass your own factory to get correct sizes.
        :return:
        """
        if manifest_factory is None:
            manifest_factory = ManifestFactory()

        num_pointers_per_node = cls._calculate_max_pointers(max_packet_size=max_packet_size,
                                                            manifest_factory=manifest_factory)

        if num_pointers_per_node < 2:
            raise ValueError("With a max_packet_size of %r there is only %r pointers per node, must have at least 2" %
                             (max_packet_size, num_pointers_per_node))

        if max_tree_degree is not None:
            num_pointers_per_node = min(num_pointers_per_node, max_tree_degree)

        solution = cls._optimize_tree(total_direct_nodes=len(file_chunks), num_pointers_per_node=num_pointers_per_node)
        return cls(file_chunks=file_chunks, max_packet_size=max_packet_size, solution=solution)

    def __init__(self, file_chunks, max_packet_size, solution):
        """

        :param file_chunks: A Pointers
        :param max_packet_size:
        """
        self._max_size = max_packet_size
        self._total_direct_nodes = len(file_chunks)
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
        return self._solution.total_nodes()

    # def total_internal_direct(self):
    #     """
    #     The number of direct objects pointed to by an internal manifest node.  An internal manifest node
    #     is one that has both direct and indirect pointers.  A leaf manifest node has only direct pointers.
    #     :return:
    #     """
    #     return self._total_internal_direct

    @staticmethod
    def _build_manifest_packet(manifest_factory, num_hashes, hv):
        # we will assume a SHA256 hash
        hashes = num_hashes * [hv]
        ptrs = Pointers(hash_values=hashes)

        # Pass values for each item so if the tree options allow it, they will be put in the manifest
        packet = manifest_factory.build_packet(source=ptrs, node_subtree_size=1000,
                                               group_subtree_size=1000, group_leaf_size=1000)

        return packet

    @classmethod
    def _calculate_max_pointers(cls, max_packet_size, manifest_factory):
        """
        Create a Manifest with the specified number of tree pointers and figure out how much space we have left
        out of self._max_size.  The figure out how many data pointers we can fit in.

        We only put metadata and locators and things like that in the root manifest.

        :param max_packet_size: The maximum ccnpy.Packet size (bytes)
        :param manifest_factory: Factory used to create manifests
        :return: The number of data points we can fit in a max_size nameless manifest
        """
        hv = HashValue.create_sha256(32 * [0])
        hash_value_len = len(hv)
        packet = cls._build_manifest_packet(manifest_factory, 1, hv)
        length = len(packet)
        if length >= max_packet_size:
            raise ValueError("An empty manifest packet is %r bytes and exceeds max_size %r" % (length, max_packet_size))

        slack = max_packet_size - length
        # +1 because we already have 1 hash in the manifest
        num_hashes = int(slack / hash_value_len) + 1
        #print("empty manifest length = %r, num_hashes = %r" % (length, num_hashes))

        # Now validate that it works

        packet = cls._build_manifest_packet(manifest_factory, num_hashes, hv)
        length = len(packet)
        if length >= max_packet_size:
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
    def _optimize_tree(total_direct_nodes, num_pointers_per_node):
        to = TreeOptimizer(total_direct_nodes=total_direct_nodes,
                           num_pointers=num_pointers_per_node)
        solutions = to.minimize_waste()
        # the results are sorted by m (number of indirect pointers per node), so pick something in the middle
        middle_solution = solutions[int(len(solutions) / 2)]
        return middle_solution
