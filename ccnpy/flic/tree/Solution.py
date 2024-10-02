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


class Solution:
    def __init__(self, total_direct_nodes, num_pointers, direct_per_node, indirect_per_node, num_internal_nodes, waste):
        self._total_direct_nodes = total_direct_nodes
        self._num_pointers = num_pointers
        self._direct_per_node = direct_per_node
        self._indirect_per_node = indirect_per_node
        self._num_internal_nodes = num_internal_nodes
        self._waste = waste

    def __repr__(self):
        return "{Solution n=%r, p=%r, d=%r, m=%r, k=%r, w=%r}" % (
            self._total_direct_nodes,
            self._num_pointers,
            self._direct_per_node,
            self._indirect_per_node,
            self._num_internal_nodes,
            self._waste
        )

    def total_direct_nodes(self):
        return self._total_direct_nodes

    def num_pointers(self):
        return self._num_pointers

    def direct_per_node(self):
        return self._direct_per_node

    def indirect_per_node(self):
        return self._indirect_per_node

    def num_internal_nodes(self):
        return self._num_internal_nodes

    def total_nodes(self):
        internal_direct = self._direct_per_node * self._num_internal_nodes
        remaining = self._total_direct_nodes - internal_direct
        capacity = self._direct_per_node + self._indirect_per_node
        leaf_nodes = int(math.ceil(remaining / capacity))
        return self._num_internal_nodes + leaf_nodes

    def waste(self):
        """
        waste is the number of unused direct pointers over the whole tree

        :return:
        """
        return self._waste
