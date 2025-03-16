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
from typing import List, Optional
from xml.etree.ElementInclude import include

from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.LeafSize import LeafSize
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.NodeData import NodeData
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from .ManifestTreeOptions import ManifestTreeOptions
from .tlvs.NcDef import NcDef
from .tlvs.NcId import NcId
from .tlvs.StartSegmentId import StartSegmentId
from .tree.ManifestGraph import ManifestGraph
from .tree.TreeBuildReturnValue import TreeBuilderReturnValue
from ..core.ExpiryTime import ExpiryTime
from ..core.Name import Name
from ..core.Packet import Packet
from ..crypto.Signer import Signer


class ManifestFactory:
    """
    Streamlines building a Manifest from a source.  The source may be any of `Pointers` or
    `HashGroup` or `Node`.  The factory can also apply a `ManifestEncryptor` and generate
    encrypted manifests.

    This class is used by ManifestTree (and others), which is the top-level interface to FLIC.
    """

    def __init__(self, tree_options: ManifestTreeOptions, manifest_graph: Optional[ManifestGraph] = None):
        """
        When passing tree options, note that they will only be applied if you construct the manifest at a
        lower level of abstraction than an option applies to.  For example, if you pass a `Node`,
        we cannot add anything.  If you use a HashGroup, we can add a NodeData.  If you pass a Pointers,
        we can add GroupData and NodeData.

        :param tree_options: options guide how manifest is built.
        :param manifest_graph: If not none, any created manifests will be added to the graph
        """
        self._encryptor = tree_options.manifest_encryptor
        self._tree_options = tree_options
        self._manifest_graph = manifest_graph
        self.cnt_manifests = 0
        self.cnt_manifest_bytes = 0

    def tree_options(self) -> ManifestTreeOptions:
        return self._tree_options

    def build_packet(self, source,
                     nc_defs: Optional[List[NcDef]] = None,
                     node_subtree_size: Optional[int] = None,
                     group_subtree_size: Optional[int] = None,
                     group_leaf_size: Optional[int] = None,
                     nc_id: Optional[NcId] = None,
                     start_segment_id: Optional[StartSegmentId] = None,
                     name: Optional[Name] = None,
                     expiry_time: Optional[ExpiryTime] = None,
                     signer: Optional[Signer] = None,
                     include_full_security_context: bool = False) -> Packet:
        """
        Calls `build()` and then construct a content object and packet to contain it.  Includes a maniest expiry time
        from tree_options.

        :param source: A Node, or a list of pointers, or a list of hash groups
        :param node_subtree_size:
        :param group_subtree_size:
        :param group_leaf_size:
        :param nc_defs: A list of name contructor definitions to include in the NodeData
        :param name: The CCNx name to put in the packet
        :param include_full_security_context: If the encryptor has the option of including a larger security context, do it.
        :return:
        """
        rv = self._build(source=source,
                         nc_defs = nc_defs,
                         node_subtree_size=node_subtree_size,
                         group_subtree_size=group_subtree_size,
                         group_leaf_size=group_leaf_size,
                         nc_id=nc_id,
                         start_segment_id=start_segment_id,
                         include_full_security_context=include_full_security_context)

        body = rv.manifest.content_object(name=name,
                                          expiry_time=expiry_time)

        if signer is not None:
            validation_alg = self._tree_options.signer.validation_alg()
            validation_payload = self._tree_options.signer.sign(body.serialize(), validation_alg.serialize())
            packet = Packet.create_signed_content_object(body, validation_alg, validation_payload)
        else:
            packet = Packet.create_content_object(body)

        if self._manifest_graph is not None:
            self._manifest_graph.add_manifest(hash_value=packet.content_object_hash(),
                                              node=rv.node,
                                              name=packet.body().name())
        self.cnt_manifests += 1
        self.cnt_manifest_bytes += len(packet)
        return packet

    def _build(self, source,
              nc_defs: Optional[List[NcDef]] = None,
              node_subtree_size: Optional[int] = None,
              group_subtree_size: Optional[int] = None,
              group_leaf_size: Optional[int] = None,
              nc_id: Optional[NcId] = None,
              start_segment_id: Optional[StartSegmentId] = None,
              include_full_security_context: bool = False) -> TreeBuilderReturnValue:
        """
        depending on the level of control you wish to have over the manifest creation, you can
        pass one of several types as the source.

        The optional arguments are used to build NodeData and GroupData structures if not already present
        and if required by the ManifestTreeOptions.

        :param source: One of Pointers or HashGroups or Node
        :param nc_defs: A list of name contructor definitions to include in the NodeData
        :param nc_id: The NcId to put in the hash group data (only applies if building from pointers).
        :param start_segment_id: The start_segment_id to put in group data (applies to only pointers)
        :param node_subtree_size: If not None and ManifestTreeOptions.add_node_subtree_size is True,
                                    add a NodeData with the subtree size.
        :param group_subtree_size: If not None and ManifestTreeOptions.add_group_subtree_size is True and
                                    there is only one HashGroup, add a GroupData with subtree size to the HashGroup.
        :param group_leaf_size: If not None and ManifestTreeOptions.add_group_leaf_size is True and
                                    there is only one HashGroup, add a GroupData with leaf size to the HashGroup.
        :return: A Manifest.ReturnValue
        """
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
            group_leaf_size = LeafSize(group_leaf_size)

        if isinstance(source, Pointers):
            rv = self._build_from_pointers(pointers=source,
                                                 nc_defs=nc_defs,
                                                 node_subtree_size=node_subtree_size,
                                                 group_subtree_size=group_subtree_size,
                                                 group_leaf_size=group_leaf_size,
                                                 nc_id=nc_id,
                                                 start_segment_id=start_segment_id,
                                                 include_full_security_context=include_full_security_context)
        elif isinstance(source, HashGroup):
            rv = self._build_node_from_hashgroups(hash_groups=[source],
                                                  nc_defs=nc_defs,
                                                  node_subtree_size=node_subtree_size,
                                                  include_full_security_context=include_full_security_context)

        elif isinstance(source, List):
            rv = self._build_node_from_hashgroups(hash_groups=source,
                                                  nc_defs=nc_defs,
                                                  node_subtree_size=node_subtree_size,
                                                  include_full_security_context=include_full_security_context)
        elif isinstance(source, Node):
            rv = self._build_from_node(source, include_full_security_context)
        else:
            raise TypeError("Unsupported type for source: %r" % source)

        if len(rv.manifest) > self._tree_options.max_packet_size:
            raise ValueError(f"The manifest is {len(rv.manifest)} bytes and exeeds max_packet_size of {self._tree_options.max_packet_size}: {rv.manifest}")
        return rv

    def _build_from_pointers(self, pointers,
                             nc_defs: Optional[List[NcDef]] = None,
                             node_subtree_size: Optional[SubtreeSize] = None,
                             group_subtree_size: Optional[SubtreeSize] = None,
                             group_leaf_size: Optional[LeafSize] = None,
                             nc_id: Optional[NcId] = None,
                             start_segment_id: Optional[StartSegmentId] = None,
                             include_full_security_context: bool = False) -> TreeBuilderReturnValue:
        """
        From a Pointers object or a list of hash values, build a Manifest.  If the encryptor is
        not None, it will be an encrypted Manifest.

        :param nc_id: If specified, will be put in the hash group data.
        """
        group_data = None
        if group_subtree_size is not None or group_leaf_size is not None or nc_id is not None or start_segment_id is not None:
            group_data = GroupData(subtree_size=group_subtree_size,
                                   leaf_size=group_leaf_size,
                                   nc_id=nc_id,
                                   start_segment_id=start_segment_id)

        hg = HashGroup(pointers=pointers, group_data=group_data)
        return self._build_node_from_hashgroups(
            hash_groups=[hg],
            nc_defs=nc_defs,
            node_subtree_size=node_subtree_size,
            include_full_security_context=include_full_security_context)

    def _build_node_from_hashgroups(self,
                                    hash_groups: List[HashGroup],
                                    nc_defs: Optional[List[NcDef]] = None,
                                    node_subtree_size: Optional[SubtreeSize] = None,
                                    include_full_security_context: bool = False) -> TreeBuilderReturnValue:
        """
        A Node may be one or more hash groups.  In practice, we usually have only one or two hash groups, depending
        on the name constrictors or locators.
        """
        node_data = None
        if node_subtree_size is not None or nc_defs is not None:
            node_data = NodeData(subtree_size=node_subtree_size, nc_defs=nc_defs)

        node = Node(node_data=node_data, hash_groups=hash_groups)
        return self._build_from_node(node, include_full_security_context)

    def _build_from_node(self, node, include_full_security_context: bool) -> TreeBuilderReturnValue:
        if self._encryptor is None:
            return TreeBuilderReturnValue(manifest=Manifest(node=node), node=node)
        else:
            return self._encrypt(node, include_full_security_context)

    def _encrypt(self, node: Node, include_full_security_context: bool) -> TreeBuilderReturnValue:
        assert self._encryptor is not None
        security_ctx, encrypted_node, auth_tag = self._encryptor.encrypt(node=node, include_wrapper=include_full_security_context)
        manifest = Manifest(security_ctx=security_ctx, node=encrypted_node, auth_tag=auth_tag)
        return TreeBuilderReturnValue(manifest=manifest, node=node)
