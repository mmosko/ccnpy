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
import logging
import math


class OptimizerResult:
    """
    Determines tree structure based on certain input parameters.  It's main job is to calculate the total number
    of nodes in the tree given assumptions about the tree structure.

    OptimizerResult is created by `TreeOptimizer` and then put into a `TreeParameters` for use by `TreeBuilder`.
    """
    logger = logging.getLogger(__name__)

    def __init__(self, num_data_objects, num_pointers, direct_per_node, indirect_per_node, num_internal_nodes, waste):
        """
        :param num_data_objects: The required number of direct pointers (i.e. number of data objects)
        :param num_pointers: The total number of pointers per manifest (= direct + indirect)
        :param direct_per_node: The max number of direct points per node
        :param indirect_per_node: The max number of indirect pointers per node
        :param num_internal_nodes: The number of internal manifest nodes in the tree
        :param waste: A measure of the wasted space in the tree
        """
        self._num_data_objects = num_data_objects
        self._num_pointers = num_pointers
        self._direct_per_node = direct_per_node
        self._indirect_per_node = indirect_per_node
        self._num_internal_nodes = num_internal_nodes
        self._waste = waste
        self._num_leaf_nodes = self._calculate_num_leaf_nodes()
        # we might be asked for this many times, so cacheit
        self._tree_height = self._calculate_tree_height()
        self._sanity_check()

    def __repr__(self):
        return "{OptResult n=%r, p=%r, dir=%r, ind=%r, int=%r, leaf=%r, w=%r, h=%r}" % (
            self._num_data_objects,
            self._num_pointers,
            self._direct_per_node,
            self._indirect_per_node,
            self._num_internal_nodes,
            self._num_leaf_nodes,
            self._waste,
            self._tree_height
        )

    def _calculate_tree_height(self):
        """
        The number of nodes in a k-ary tree is:
            n = (k^(h+1)-1)/(k-1)

        So the height of a k-ary tree with n nodes is:
            h = log_k((k-1) * n + 1) - 1
        """
        if self._indirect_per_node == 1:
            # a chain
            return self.total_nodes()

        if self._indirect_per_node == 0:
            # a tree with data only at the leaves
            # we need _num_data_objects leaf pointers, so that happens at
            return int(math.ceil(math.log(self._num_data_objects, self._direct_per_node)))

        k = self._indirect_per_node
        n = self.total_nodes()
        arg = (k-1) * n + 1
        return int(math.ceil(math.log(arg, self._indirect_per_node) - 1))

    def _calculate_num_leaf_nodes(self):
        num_internal_direct = self._num_internal_nodes * self._direct_per_node
        remaining = self._num_data_objects - num_internal_direct
        if remaining <= 0:
            self.logger.debug(f"internal capacity is {num_internal_direct}, so no leaf nodes required, remaining = {remaining}")
            return 0
        leaf_capacity = self._num_pointers
        leaf_nodes = int(math.ceil(remaining / leaf_capacity))
        return leaf_nodes

    def _sanity_check(self):
        if not self._direct_per_node + self._indirect_per_node == self._num_pointers:
            raise ValueError(f'direct {self._direct_per_node} + indirect {self._indirect_per_node} != total {self._num_pointers}')

        capacity = self._num_leaf_nodes * self._num_pointers + self._num_internal_nodes * self._direct_per_node
        if not capacity >= self._num_data_objects:
            raise ValueError(f'capacity {capacity} < num data objects {self._num_data_objects}')

        # if not capacity == self._num_data_objects + self._waste:
        #     raise ValueError(f'Waste {self.waste()} != capacity {capacity} - num data objects {self._num_data_objects}')

    def num_data_objects(self):
        """The number of data objects"""
        return self._num_data_objects

    def num_pointers(self):
        """The maximum number of pointers per manifest node"""
        return self._num_pointers

    def direct_per_node(self):
        """The number of direct pointers per non-leaf node"""
        return self._direct_per_node

    def indirect_per_node(self):
        """The number of indirect points per non-leaf node"""
        return self._indirect_per_node

    def num_internal_nodes(self):
        """The number of internal (non-leaf) manifest nodes"""
        return self._num_internal_nodes

    def num_leaf_nodes(self):
        """The number of leaf manifest nodes"""
        return self._num_leaf_nodes

    def total_nodes(self):
        """The total number of manifest nodes (leaf + internal)"""
        return self.num_internal_nodes() + self.num_leaf_nodes()

    def waste(self):
        """
        waste is the number of unused direct pointers over the whole tree

        :return:
        """
        return self._waste

    def tree_height(self) -> int:
        """
        The total tree height, including leaf nodes.
        """
        # Internal nodes are limited to `internal_indirect_per_node()` indirect pointers, so that is the tree
        # degree.  leaf nodes only point to data, so do not add to the tree height below them.
        return self._tree_height
