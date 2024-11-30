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


from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.flic.tree.ManifestIdFactory import ManifestIdFactory
from ccnpy.flic.tree.OptimizerResult import OptimizerResult


class ManifestIdFactoryTest(CcnpyTestCase):

    def test_degree_one(self):
        # this is a chain, not a tree
        factory = ManifestIdFactory(tree_degree=1, max_height=5)

        expected = [0, 1, 2, 3, 4, 5]
        self.assertEqual(expected, factory._next_ids)

    def test_degree_two(self):
        factory = ManifestIdFactory(tree_degree=2, max_height=5)

        expected = [0, 2, 6, 14, 30, 62]
        self.assertEqual(expected, factory._next_ids)

    def test_degree_three(self):
        factory = ManifestIdFactory(tree_degree=3, max_height=5)

        expected = [0, 3, 12, 39, 120, 363]
        self.assertEqual(expected, factory._next_ids)

    def test_degree_four(self):
        factory = ManifestIdFactory(tree_degree=4, max_height=5)

        expected = [0, 4, 20, 84, 340, 1364]
        self.assertEqual(expected, factory._next_ids)

    def test_get_next(self):
        factory = ManifestIdFactory(tree_degree=4, max_height=5)

        first = [factory.get_next_id(h) for h in range(0,6)]
        self.assertEqual([0, 4, 20, 84, 340, 1364], first)

        second = [factory.get_next_id(h) for h in range(1,6)]
        self.assertEqual([3, 19, 83, 339, 1363], second)

        with self.assertRaises(OverflowError):
            factory.get_next_id(0)

        self.assertEqual(2, factory.get_next_id(1))
        self.assertEqual(1, factory.get_next_id(1))
        self.assertEqual(0, factory.get_next_id(1))

        with self.assertRaises(OverflowError):
            factory.get_next_id(1) # overflow
