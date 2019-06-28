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


class ManifestTreeOptions:
    def __init__(self,
                 root_expiry_time=None,
                 manifest_expiry_time=None,
                 data_expiry_time=None,
                 manifest_encryptor=None,
                 add_group_subtree_size=False,
                 add_group_leaf_size=False,
                 add_node_subtree_size=True):
        """
        :param root_expiry_time: The ContentObject expiry time for the root manifest
        :param manifest_expiry_time: The ContentObject expiry time for non-root nameless manifests
        :param data_expiry_time: The ContentObject expiry time for the data content objects
        :param manifest_encryptor: (optional) The ccnpy.flic.ManifestEncryptor to encrypt manifests
        :param add_group_subtree_size: If True, add a GroupData with SubtreeSize to each manifest
        :param add_group_leaf_size: If True, add a GroupData with LeafSize to each manifest
        :param add_node_subtree_size: If True, add a NodeData with SubtreeSize to each manifest
        """
        self.root_expiry_time = root_expiry_time
        self.manifest_expiry_time = manifest_expiry_time
        self.data_expiry_time = data_expiry_time
        self.manifest_encryptor = manifest_encryptor
        self.add_group_subtree_size = add_group_subtree_size
        self.add_group_leaf_size = add_group_leaf_size
        self.add_node_subtree_size = add_node_subtree_size
