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

import ccnpy


class GroupData(ccnpy.TlvType):
    __type = 0x0001
    __subtree_size_type = 0x0001
    __subtree_digest_type = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, leaf_size=None, leaf_digest=None,
                 subtree_size=None, subtree_digest=None, size_index=None, locators=None):
        ccnpy.TlvType.__init__(self)

