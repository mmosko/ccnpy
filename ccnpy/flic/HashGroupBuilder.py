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

from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ..core.HashValue import HashValue


class HashGroupBuilder:
    """
    A utility class to build a HashGroup.  It allows you to append pointers one by one.  It will keep track of
    the total direct data size and total indirect size.
    """
    def __init__(self, max_direct=math.inf, max_indirect=math.inf):
        self._pointers = []
        self._direct_size = 0
        self._indirect_size = 0
        self._direct_count = 0
        self._indirect_count = 0
        self._max_direct = max_direct
        self._max_indirect = max_indirect

    def is_direct_full(self):
        return self._direct_count >= self._max_direct

    def append_direct(self, hash_value, leaf_size=None):
        """
        Appends a pointer to a single data Content Object
        :param hash_value:
        :param leaf_size:
        :return:
        """
        assert self._direct_count < self._max_direct

        self._pointers.append(hash_value)
        self._direct_count += 1
        if leaf_size is not None:
            self._direct_size += leaf_size

    def prepend_direct(self, hash_value: HashValue, leaf_size: int=None):
        """
        Prepends a pointer to a single data Content Object
        :param hash_value:
        :param leaf_size:
        :return:
        """
        assert self._direct_count < self._max_direct

        self._pointers.insert(0, hash_value)
        self._direct_count += 1
        if leaf_size is not None:
            self._direct_size += leaf_size

    def is_indirect_full(self):
        return self._indirect_count >= self._max_indirect

    def append_indirect(self, hash_value, subtree_size=None):
        """
        Append a pointer to an indirect child manifest
        :param hash_value:
        :param subtree_size:
        :return:
        """
        assert self._indirect_count < self._max_indirect

        self._pointers.append(hash_value)
        self._indirect_count += 1
        if subtree_size is not None:
            self._indirect_size += subtree_size

    def prepend_indirect(self, hash_value, subtree_size=None):
        """
        Append a pointer to an indirect child manifest
        :param hash_value:
        :param subtree_size:
        :return:
        """
        assert self._indirect_count < self._max_indirect

        self._pointers.insert(0, hash_value)
        self._indirect_count += 1
        if subtree_size is not None:
            self._indirect_size += subtree_size

    def pointers(self):
        """

        :return: ccnpy.flic.Pointers object
        """
        return Pointers(hash_values=self._pointers)

    def direct_count(self):
        return self._direct_count

    def direct_size(self):
        """
        :return: The number of bytes used by the direct pointers
        """
        return self._direct_size

    def indirect_count(self):
        return self._indirect_count

    def indirect_size(self):
        """
        :return: The number of bytes used by the indirect pointers
        """
        return self._indirect_size

    def hash_group(self, include_leaf_size=False, include_subtree_size=False):
        """
        TODO: leaf_size is not implemented

        :param include_leaf_size:
        :param include_subtree_size:
        :return:
        """
        gd = None
        if include_leaf_size or include_subtree_size:
            subtree_size = subtree_digest = None
            if include_subtree_size:
                subtree_size = SubtreeSize(self.indirect_size())
            gd = GroupData(subtree_size=subtree_size, subtree_digest=subtree_digest)

        hg = HashGroup(group_data=gd, pointers=self.pointers())
        return hg
