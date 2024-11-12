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


class ManifestIdFactory:
    """
    Manifest IDs (used by SegmentedSchema) are generated per tree level.  This means we can generate
    sequential IDs within each hash group.  The IDs will be globally unique.  They will not necessarily
    be compact.  We might skip a few if we do not have a full tree.
    """

    def __init__(self, tree_degree: int, max_height: int):
        self._tree_degree = tree_degree
        self._max_height = max_height

        self._next_ids = [self._last_id_for_height(h) for h in range(0, max_height+1)]

    def _last_id_for_height(self, h):
        """
        The last ID of height h for degree k is
            (k^(h+1)-1)/(k-1) - 1

        This comes from the number of nodes per level for a k-ary tree.
        """
        if self._tree_degree == 1:
            return h
        assert self._tree_degree > 1
        return int((pow(self._tree_degree, (h+1))-1) / (self._tree_degree-1) - 1)

    def get_next_id(self, height) -> int:
        next_id = self._next_ids[height]
        if next_id < 0:
            raise OverflowError(f"Too many IDs retrieved from height {height}: {self._next_ids}")

        self._next_ids[height] = next_id - 1
        return next_id

