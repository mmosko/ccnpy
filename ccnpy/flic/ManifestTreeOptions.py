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

from dataclasses import dataclass
from typing import Optional

from ccnpy.flic.tlvs.Locators import Locators
from .ManifestEncryptor import ManifestEncryptor
from .name_constructor.SchemaType import SchemaType
from ..core.ExpiryTime import ExpiryTime
from ..core.Name import Name
from ..crypto.Signer import Signer


@dataclass
class ManifestTreeOptions:
    """
    Options that guide how to build the manifest tree.

    Attributes:
        name: The root manifest name.
        schema_type: The type of name constructor to use.
        signer: The root manifest signer.

        root_expiry_time: The ContentObject expiry time for the root manifest
        manifest_expiry_time: The ContentObject expiry time for non-root manifests
        data_expiry_time: The ContentObject expiry time for the data content objects
        manifest_encryptor: The ccnpy.flic.ManifestEncryptor to encrypt manifests

        add_group_subtree_size: If True, add a GroupData with SubtreeSize to each manifest
        add_group_leaf_size: If True, add a GroupData with LeafSize to each manifest
        add_node_subtree_size: If True, add a NodeData with SubtreeSize to each manifest
        max_tree_degree: The maximum tree degree, limited by the packet size.  None for unlimited.
        debug: Print debugging messages
    """

    name: Name
    schema_type: SchemaType
    signer: Signer
    manifest_prefix: Optional[Name] = None
    data_prefix: Optional[Name] = None

    manifest_locators: Optional[Locators] = None
    data_locators: Optional[Locators] = None

    root_expiry_time: Optional[ExpiryTime] = None
    manifest_expiry_time: Optional[ExpiryTime] = None
    data_expiry_time: Optional[ExpiryTime] = None
    manifest_encryptor: Optional[ManifestEncryptor] = None

    add_node_subtree_size: bool = False
    add_node_subtree_digest: bool = False
    add_group_subtree_size: bool = False
    add_group_subtree_digest: bool = False
    add_group_leaf_size: bool = False
    add_group_leaf_digest: bool = False

    max_tree_degree: Optional[int] = None
    max_packet_size: int = 1500
    debug: bool = False
