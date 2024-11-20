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

from .OptimizerResult import OptimizerResult


class TreeOptimizer:
    """
    We build a tree where internal nodes have d direct pointers and m indirect pointers.
    A direct pointer locates a file block and an indirect pointer locates another internal node.
    A leaf node has up to d+m direct pointers.  This algorithm will build a compact m-ary regular
    tree.

    TreeOptimizer does not consider that there may be 1 or 2 hash groups per manifest.  If the initial calculation
    on the number of pointers that can fit in a packet considered 2 hash groups (e.g. Segmented Schema), but there
    turn out to only be one type (e.g. a leaf manifest with only direct pointers), there will be 4 wasted bytes
    due to the missing indirect hash group.  To fix this shortcomming, we should consider the number of pointers
    available for mixed manifests and single-purpose manifests.

    Let k be the number of internal nodes and n be the number of direct pointers.  We have
    k * m total indirect pointers, but the k internal nodes use k-1 of the pointers, so here
    are lp = k * m - (k-1) leaf pointers.

    In a (k, m, d)-tree, we have:
        n = k * d + lp * (d + m)

    If we are given a file that requires n direct pointers, we solve for k as:
         N(k, d, m) = k * (d*m + m^2 - m) + d + m
         K(n, d, m) = ceil((n - d - m) / ( m * (d + m -1)))

    The ceiling function is because we need to round up when the number of direct pointers is between full trees.
    Note that from 0 < n < d+m, the ceiling argument will be a negative fraction.

    For a desired n, we can optimize the choice of m and d to minimize the waste.
        q = d + m, where q is fixed, d and m are integers
        n is fixed integer
        waste = w(d, m) = N( K(d, m), d, m) - n

    Because K(d,m) has a ceiling function, it must be evaluated in the limit from left and right at each
    point of discontinuity.  Because q will be a small number, such as 25, we instead can use a linear search:

        (d*, m*) = argmin_(d in Z+, m in Z>=: d+m=q) w(d,m)

    Another approach is to minimize K, as that would minimize the number of indirect reads:

        k* = argmin_(d, m) K(n, d, m)

    Once we know the number of internal nodes, we find the tree height as h = ceil( log_m( (m-1) * k + 1) - 1).
    The height of a tree is its longest path length, so a tree with only the root node has a height of 0.
    """

    def __init__(self, num_direct_nodes: int, num_pointers: int):
        """

        :param num_direct_nodes: The total number of direct pointers needed
        :param num_pointers: The number of pointers (direct or indirect) per internal node
        """
        self._num_direct_nodes = num_direct_nodes
        self._num_pointers = num_pointers

    def calculate_k(self, d, m):
        """
        Calculate the number of interior nodes needed for the given (d, m).

        :param d: Number of direct pointers
        :param m: Number of indirect pointers
        :return:
        """
        if m == 0:
            if self._num_direct_nodes > d:
                return math.inf
            else:
                return 1

        k = math.ceil((self._num_direct_nodes - d - m) / (m * (d + m - 1)))
        return k

    @staticmethod
    def calculate_n(k, d, m):
        """
        For a given number of internal nodes, calculate its capacity for direct nodes

        :param k: the number of internal nodes
        :param d: direct pointers per node
        :param m: indirect pointers per node
        :return:
        """
        n = k * (d*m + m*m - m) + d + m
        return n

    def minimize_k(self):
        """
        Determine the (d, m) that minimizes k.

        :return: A list of Solution tuples.  The list will be sorted in order of fanout (m), with the first
        element with the lowest fanout.
        """
        best_k = math.inf
        #Solution = collections.namedtuple('Solution', 'd m k w')
        best_solutions = []

        for m in range(0, self._num_pointers):
            d = self._num_pointers - m
            k = self.calculate_k(d, m)
            if k < math.inf:
                w = self.calculate_waste(k, d, m)
                solution = OptimizerResult(self._num_direct_nodes, self._num_pointers, d, m, k, w)
                if k < best_k:
                    best_k = k
                    best_solutions = [solution]
                elif k == best_k:
                    best_solutions.append(solution)

        #print("Min k    : best solutions: %r" % best_solutions)
        return best_solutions

    def minimize_k_min_waste(self)-> OptimizerResult:
        solutions = self.minimize_k()
        best_solution = None
        min_waste = math.inf
        for s in solutions:
            if s.waste() < min_waste:
                best_solution = s
                min_waste = s.waste()
        assert best_solution is not None
        return best_solution

    def minimize_waste_min_height(self) -> OptimizerResult:
        """
        A minimum waste solution of minimum height
        """
        solutions = self.minimize_waste()
        print(solutions)
        min_height = 0xFFFFFFFF
        min_solution = None
        for s in solutions:
            if s.tree_height() < min_height:
                min_height = s.tree_height()
                min_solution = s
        assert min_solution is not None
        return min_solution

    def minimize_waste(self):
        """
        Determine the (d, m) that minimizes k.

        :return: A list of Solution tuples.  The list will be sorted in order of fanout (m), with the first
        element with the lowest fanout.
        """
        best_w = math.inf
        #Solution = collections.namedtuple('Solution', 'd m k w')
        best_solutions = []

        for m in range(0, self._num_pointers):
            d = self._num_pointers - m
            k = self.calculate_k(d, m)
            w = self.calculate_waste(k, d, m)
            if w < best_w:
                best_w = w
                solution = OptimizerResult(self._num_direct_nodes, self._num_pointers, d, m, k, w)
                best_solutions = [solution]
                # print("best so far %r" % best_solutions)

            elif w == best_w:
                solution = OptimizerResult(self._num_direct_nodes, self._num_pointers, d, m, k, w)
                best_solutions.append(solution)

        #print("Min Waste: best solutions: %r" % best_solutions)
        #print("Min Waste max m: %r" % (best_solutions[-1],))
        #print("Min waste mid m: %r" % (best_solutions[int(len(best_solutions)/2)],))
        #print("largest k best solution: %r" %
        return best_solutions

    def calculate_waste(self, k, d, m):
        n = self.calculate_n(k, d, m)
        waste = n - self._num_direct_nodes
        return waste
