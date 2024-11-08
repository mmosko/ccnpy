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

from ccnpy.flic.tree.Solution import Solution


class SolutionTest(unittest.TestCase):

    def test_one(self):
        # this is not an optimal design
        s = Solution(num_data_objects=6, num_pointers=3, direct_per_node=1, indirect_per_node=2, num_internal_nodes=5, waste=2)
        self.assertEqual(6, s.num_data_objects())
        self.assertEqual(3, s.num_pointers())
        self.assertEqual(1, s.direct_per_node())
        self.assertEqual(2, s.indirect_per_node())
        self.assertEqual(5, s.num_internal_nodes())
        self.assertEqual(2, s.waste())
        # 5 internal nodes = 5 direct pointers, plus 1 leaf node = 8 direct pointers
        self.assertEqual(1, s.num_leaf_nodes())
        self.assertEqual(6, s.total_nodes())

    def test_two(self):
        # this is optimal
        s = Solution(num_data_objects=6, num_pointers=3, direct_per_node=1, indirect_per_node=2, num_internal_nodes=1, waste=1)
        self.assertEqual(6, s.num_data_objects())
        self.assertEqual(3, s.num_pointers())
        self.assertEqual(1, s.direct_per_node())
        self.assertEqual(2, s.indirect_per_node())
        self.assertEqual(1, s.num_internal_nodes())
        self.assertEqual(1, s.waste())
        # 1 internal node = 1 direct pointers, plus 2 leaf node = 6 direct pointers
        self.assertEqual(2, s.num_leaf_nodes())
        self.assertEqual(3, s.total_nodes())