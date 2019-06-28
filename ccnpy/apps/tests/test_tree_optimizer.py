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

import unittest
import random
import math
import ccnpy.apps


class test_tree_optimizer(unittest.TestCase):

    def test_minimize_k(self):
        KB = 1000
        MB = 1000 * KB
        GB = 1000 * MB
        file_size = int(random.random() * GB)
        block_size = 1200
        direct_nodes = int(math.ceil(file_size / block_size))

        print("Solving for BS %r FS %r NODES %r" % (block_size, file_size, direct_nodes))
        tb = ccnpy.apps.TreeOptimizer(total_direct_nodes=direct_nodes, num_pointers=12)
        tb.minimize_k()
        tb.minimize_waste()
