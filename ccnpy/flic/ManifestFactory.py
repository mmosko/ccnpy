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
from .GroupData import GroupData
from .HashGroup import HashGroup
from .LocatorList import LocatorList
from .Manifest import Manifest
from .ManifestEncryptor import ManifestEncryptor
from .ManifestTreeOptions import ManifestTreeOptions
from .Node import Node
from .NodeData import NodeData
from .Pointers import Pointers
from .SubtreeSize import SubtreeSize


class ManifestFactory:
    """
    Streamlines building a Manifest from a source.  The source may be any of `Pointers` or
    `HashGroup` or `Node`.  The factory can also apply a `ManifestEncryptor` and generate
    encrypted manifests.
    """
    def __init__(self, encryptor=None, tree_options=None):
        """
        When passing tree options, note that they will only be applied if you construct the manifest at a
        lower level of abstraction than an option applies to.  For example, if you pass a `Node`,
        we cannot add anything.  If you use a HashGroup, we can add a NodeData.  If you pass a Pointers,
        we can add GroupData and NodeData.

        TODO: manifest_encryptor is not a field in tree_options, so should change the signature of this method.

        :param encryptor: (optional) Used to encrypt the manifest
        :param tree_options: (optional) If present, options guide how manifest is built, otherwise use defaults from
                            ManifestTreeOptions.
        """
        if encryptor is not None and not issubclass(encryptor.__class__, ManifestEncryptor):
            raise TypeError("Encryptor, if present, must be subclass of ManifestEncryptor")

        self._encryptor = encryptor

        if tree_options is None:
            self._tree_options = ManifestTreeOptions()
        else:
            self._tree_options = tree_options

    def build_packet(self, source, node_locators=None, node_subtree_size=None, group_subtree_size=None, group_leaf_size=None):
        """
        Calls `build()` and then construct a content object and packet to contain it.  Includes a maniest expiry time
        from tree_options.

        :param source:
        :param node_locators:
        :param node_subtree_size:
        :param group_subtree_size:
        :param group_leaf_size:
        :return:
        """
        manifest = self.build(source, node_locators, node_subtree_size, group_subtree_size, group_leaf_size)
        packet = manifest.packet(expiry_time=self._tree_options.manifest_expiry_time)
        return packet

    def build(self, source, node_locators=None, node_subtree_size=None, group_subtree_size=None, group_leaf_size=None):
        """
        depending on the level of control you wish to have over the manifest creation, you can
        pass one of several types as the source.

        The optional arguments are used to build NodeData and GroupData structures if not already present
        and if required by the ManifestTreeOptions.

        :param source: One of Pointers or HashGroup or Node
        :param node_locators: (optional) A LocatorList to include in the NodeData
        :param node_subtree_size: If not None and ManifestTreeOptions.add_node_subtree_size is True,
                                    add a NodeData with the subtree size.
        :param group_subtree_size: If not None and ManifestTreeOptions.add_group_subtree_size is True and
                                    there is only one HashGroup, add a GroupData with subtree size to the HashGroup.
        :param group_leaf_size: If not None and ManifestTreeOptions.add_group_leaf_size is True and
                                    there is only one HashGroup, add a GroupData with leaf size to the HashGroup.
        :return: A Manifest
        """
        manifest = None

        if node_locators is not None and not isinstance(node_locators, LocatorList):
            raise TypeError("node_locators must be LocatorList")

        # If the tree options do not allow adding a type of metadata, we None it out here
        if not self._tree_options.add_node_subtree_size:
            node_subtree_size = None
        if not self._tree_options.add_group_subtree_size:
            group_subtree_size = None
        if not self._tree_options.add_group_leaf_size:
            group_leaf_size = None

        # Make sure the sizes are the proper containers if we were just passed Ints
        if node_subtree_size is not None and isinstance(node_subtree_size, int):
            node_subtree_size = SubtreeSize(node_subtree_size)
        if group_subtree_size is not None and isinstance(group_subtree_size, int):
            group_subtree_size = SubtreeSize(group_subtree_size)
        if group_leaf_size is not None and isinstance(group_leaf_size, int):
            raise RuntimeError("Not implemented")
        #    group_leaf_size = Leafize(group_leaf_size)

        if isinstance(source, Pointers):
            manifest = self._build_from_pointers(source, node_locators, node_subtree_size,
                                                 group_subtree_size, group_leaf_size)
        elif isinstance(source, HashGroup):
            manifest = self._build_from_hashgroup(source, node_locators, node_subtree_size)
        elif isinstance(source, Node):
            manifest = self._build_from_node(source)
        else:
            raise TypeError("Unsupported type for source: %r" % source)

        return manifest

    def _build_from_pointers(self, pointers, node_locators=None, node_subtree_size=None,
                             group_subtree_size=None, group_leaf_size=None):
        """
        From a Pointers object or a list of hash values, build a Manifest.  If the encryptor is
        not None, it will be an encrypted Manifest.
        """
        group_data = None
        if group_subtree_size is not None or group_leaf_size is not None:
            group_data = GroupData(subtree_size=group_subtree_size, leaf_size=group_leaf_size)

        hg = HashGroup(pointers=pointers, group_data=group_data)
        return self._build_from_hashgroup(hg, node_locators, node_subtree_size)

    def _build_from_hashgroup(self, hg, node_locators=None, node_subtree_size=None):
        node_data = None
        if node_subtree_size is not None or node_locators is not None:
            node_data = NodeData(subtree_size=node_subtree_size, locators=node_locators)

        node = Node(node_data=node_data, hash_groups=[hg])
        return self._build_from_node(node)

    def _build_from_node(self, node):
        if self._encryptor is None:
            manifest = Manifest(node=node)
        else:
            manifest = self._encrypt(node)

        return manifest

    def _encrypt(self, node):
        assert self._encryptor is not None
        security_ctx, encrypted_node, auth_tag = self._encryptor.encrypt(node=node)
        manifest = Manifest(security_ctx=security_ctx, node=encrypted_node, auth_tag=auth_tag)
        return manifest
