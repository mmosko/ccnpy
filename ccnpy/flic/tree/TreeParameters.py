#  Copyright 2019 Marc Mosko
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
import ccnpy
import ccnpy.flic


class TreeParameters:
    @classmethod
    def create_optimized_tree(cls, file_chunks, max_packet_size, max_tree_degree=None):
        """
        :param file_chunks: A Pointers object
        :param max_packet_size: Maximum byte length of a CCNx Packet
        :param max_tree_degree: Maximum degree, limited by packet size.  None means only limited by packet size.
        :return:
        """
        num_pointers_per_node = cls._calculate_max_pointers(max_packet_size=max_packet_size)
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
        :param max_size:
        """
        self._max_size = max_packet_size
        self._total_direct_nodes = len(file_chunks)
        self._num_pointers_per_node = solution.indirect_per_node() + solution.direct_per_node()
        self._solution = solution

        #self._total_internal_direct = self._solution.num_internal_nodes() * self._solution.direct_per_node()
        #self._total_leaf_direct = self._solution.total_direct_nodes() - self._total_internal_direct
        #assert self._total_leaf_direct >= 0

        #self._total_leaf_manifests = int(math.ceil(self._total_leaf_direct / self._num_pointers_per_node))

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
    def _calculate_max_pointers(max_packet_size):
        """
        Create a Manifest with the specified number of tree pointers and figure out how much space we have left
        out of self._max_size.  The figure out how many data pointers we can fit in.

        We only put metadata and locators and things like that in the root manifest.
        :return: The number of data points we can fit in a max_size nameless manifest
        """
        ctx = node = tag = None
        # we will assume a SHA256 hash
        hv = ccnpy.HashValue.create_sha256(32*[0])
        hashes = [hv]
        #print(hashes)
        ptrs = ccnpy.flic.Pointers(hash_values=hashes)
        hg = ccnpy.flic.HashGroup(group_data=None, pointers=ptrs)
        node = ccnpy.flic.Node(node_data=None, hash_groups=[hg])
        empty_manifest = ccnpy.flic.Manifest(security_ctx=ctx, node=node, auth_tag=tag)
        packet = ccnpy.Packet.create_content_object(body=ccnpy.ContentObject.create_manifest(manifest=empty_manifest))
        length=len(packet)
        if length >= max_packet_size:
            raise ValueError("An empty manifest packet is %r bytes and exceeds max_size %r" % (length, max_packet_size))

        slack = max_packet_size - length
        # +1 because we already have 1 hash in the manifest
        num_hashes = int(slack / len(hv)) + 1
        #print("empty manifest length = %r, num_hashes = %r" % (length, num_hashes))

        # Now validate that it works
        hashes = num_hashes*[hv]
        ptrs = ccnpy.flic.Pointers(hash_values=hashes)
        hg = ccnpy.flic.HashGroup(group_data=None, pointers=ptrs)
        node = ccnpy.flic.Node(node_data=None, hash_groups=[hg])
        empty_manifest = ccnpy.flic.Manifest(security_ctx=ctx, node=node, auth_tag=tag)
        length=len(empty_manifest)
        if length >= max_packet_size:
            raise ValueError("A filled manifest is %r bytes and exceeds max_size" % length)

        #print("calculate_max_pointers = %r in length %r, actual length %r" % (num_hashes, max_packet_size, length))

        if num_hashes < 2:
            min_packet_size = len(packet) + len(hv)
            raise ValueError("With max_packet_size %r there are %r hashes/manifest, must have at least 2."
                             "  Minimum packet_size is %r" % (max_packet_size, num_hashes, min_packet_size))
        return num_hashes

    @staticmethod
    def _optimize_tree(total_direct_nodes, num_pointers_per_node):
        to = ccnpy.flic.tree.TreeOptimizer(total_direct_nodes=total_direct_nodes,
                                           num_pointers=num_pointers_per_node)
        solutions = to.minimize_waste()
        # the results are sorted by m (number of indirect pointers per node), so pick something in the middle
        middle_solution = solutions[int(len(solutions)/2)]
        return middle_solution

