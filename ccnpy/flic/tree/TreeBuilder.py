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

from typing import Optional

from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.NodeData import NodeData
from .HashGroupBuilderPair import HashGroupBuilderPair
from .ManifestIdFactory import ManifestIdFactory
from .TreeParameters import TreeParameters
from ..HashGroupBuilder import HashGroupBuilder
from ..ManifestFactory import ManifestFactory
from ..ManifestTreeOptions import ManifestTreeOptions
from ..name_constructor.FileMetadata import FileMetadata
from ..name_constructor.NameConstructorContext import NameConstructorContext
from ..tlvs.StartSegmentId import StartSegmentId
from ...core.Name import Name
from ...core.Packet import Packet, PacketWriter


class TreeBuilder:
    """
    TreeBuilder will construct a pre-order tree in a single pass going from the tail of the data to the beginning.
    This allows us to create all the children of a parent before the parent, which means we can populate all the
    hash pointers.

    Pre-order traversal and the reverse pre-order traversal are shown below.  In a nutshell, we need to create the
    right-most child first, then its siblings, then the parent.

    Because we're building from the bottom up, we use the term 'level' to be the distance from the right-most child
    up.  Level 0 is the bottom-most level of the tree.

            1
        2       3
      4  5    6  7
      preorder: 1 2 4 5 3 6 7
      reverse:  7 6 3 5 4 2 1

    Code:
        preorder(node)
            if (node = null)
                return
            visit(node)
            preorder(node.left)
            preorder(node.right)

        reverse_preorder(node)
            if (node = null)
                return
            reverse_preorder(node.right)
            reverse_preorder(node.left)
            visit(node)

        build_tree(data[0..n-1], n, k, m)
            # data is the application data
            # n is the number of data items
            # k is the number of direct pointers per internal node
            # m is the number of indirect pointers per internal node

            segment = namedtuple('Segment', 'head tail')(0, n)
            level = 0

            # This bootstraps the process by creating the right most child manifest
            # A leaf manifest has no indirect pointers, so k+m are direct pointers
            root = leaf_manifest(data, segment, k + m)

            # Keep building subtrees until we're out of direct pointers
            while not segment.empty():
                level += 1
                root = bottom_up_preorder(data, segment, level, k, m, root)

            return root

        bottom_up_preorder(data, segment, level, k, m, right_most_child=None)
            manifest = None
            if level == 0:
                assert right_most_child is None
                # build a leaf manifest with only direct pointers
                manifest = leaf_manifest(data, segment, k + m)
            else:
                # If the number of remaining direct pointers will fit in a leaf node, make one of those.
                # Otherwise, we need to be an interior node
                if right_most_child is None and segment.length() <= k + m:
                    manifest = leaf_manifest(data, segment, k+m)
                else:
                    manifest = interior_manifest(data, segment, level, k, m, right_most_child)
            return manifest

        leaf_manifest(data, segment, count)
            # At most count items, but never go before the head
            start = max(segment.head(), segment.tail() - count)
            manifest = Manifest(data[start:segment.tail])
            segment.tail -= segment.tail() - start
            return manifest

        interior_manifest(data, segment, level, k, m, right_most_child)
            children = []
            if right_most_child is not None:
                children.append(right_most_child)

            interior_indirect(data, segment, level, k, m, children)
            interior_direct(data, segment, level, k, m, children)

            manifest = Manifest(children)
            return manifest, tail

        interior_indirect(data, segment, level, k, m, children)
            # Reserve space at the head of the segment for this node's direct pointers before
            # descending to children.  We want the top of the tree packed.
            reserve_count = min(m, segment.tail - segment.head)
            segment.head += reserve_count

            while len(children) < m and not segment.head == segment.tail:
                child = bottom_up_preorder(data, segment, level - 1, k, m)
                # prepend
                children.insert(0, child)

            # Pull back our reservation and put those pointers in our direct children
            segment.head -= reserve_count

        interior_direct(data, segment, level, k, m, children)
            while len(children) < k+m and not segment.head == segment.tail:
                pointer = data[segment.tail() - 1]
                children.insert(0, pointer)
                segment.tail -= 1
    """

    class ReturnValue:
        """
        A wrapper for the return tuple used in TreeBuilder.  When a manifest wraps a node, it is likely
        encrypted, so we cannot easily access the node data.  This structure makes the components more
        easily accessible while building the tree.
        """

        def __init__(self, packet, manifest, node):
            self.packet = packet
            self.manifest = manifest
            self.node = node

        def __repr__(self):
            return "{RV %r, %r}" % (self.packet.content_object_hash(), self.node)

    class Segment:
        """
        Represents a Python-like half-open range [head:tail), where
        head == tail indicates empty, and head < tail represents not empty.
        It only supports positive values, not reverse ranges using negative numbers.
        """

        def __init__(self, head, tail):
            self._head = head
            self._tail = tail
            self._assert_invariants()

        def __repr__(self):
            return "{Segment %r, %r}" % (self._head, self._tail,)

        def _assert_invariants(self):
            if self._tail < 0:
                raise ValueError("Tail is negative")
            if self._head < 0:
                raise ValueError("Head is negative")
            if self._tail < self._head:
                raise ValueError("Tail less than head")

        def tail(self):
            return self._tail

        def head(self):
            return self._head

        def decrement_tail(self, count=1):
            assert count >= 0
            self._tail -= count
            self._assert_invariants()

        def increment_head(self, count=1):
            assert count >= 0
            self._head += count
            self._assert_invariants()

        def decrement_head(self, count=1):
            assert count >= 0
            self._head -= count
            self._assert_invariants()

        def empty(self):
            return self._head == self._tail

        def length(self):
            return self._tail - self._head

    def __init__(self, file_metadata: FileMetadata, tree_parameters: TreeParameters,
                manifest_factory: ManifestFactory, packet_output: PacketWriter, tree_options: ManifestTreeOptions,
                name_ctx: NameConstructorContext):
        """

        :param file_metadata: Info about the file chunks
        :param tree_parameters:
        :param manifest_factory: ccnpy.flic.ManifestFactory
        :param packet_output: A class that has a `put(packet)` method
        :param tree_options: The user arguments to the program
        :param name_ctx: The name constructors for manifests and data

        """
        self._file_metadata = file_metadata
        self._params = tree_parameters
        self._factory = manifest_factory
        self._tree_options = tree_options
        self._packet_output = packet_output
        self._name_ctx = name_ctx

        # a counter of the number of manifests created
        self._manifest_count = 0
        self._leaf_count = 0
        self._internal_count = 0
        self._last_manifest_id = None

        self._manifest_id_factory = ManifestIdFactory(tree_degree=self._params.internal_indirect_per_node(),
                                                      max_height=self._params.tree_height())

    def name_context(self) -> NameConstructorContext:
        return self._name_ctx

    def leaf_count(self):
        return self._leaf_count

    def internal_count(self):
        return self._internal_count

    def build(self) -> Packet:
        """
        TODO: We need to get the chunk_id of each manifest node.  We know the total number of manifest nodes
        from self._params.total_nodes(), so we can work backwards from that.

        :return: The root ccnpy.Packet
        """

        # It should be true that head points to chunk 0 and tail points to the last chunk of the data,
        # with all the other chunk numbers sequentailly between.
        segment = TreeBuilder.Segment(0, len(self._file_metadata))

        # the bottom right node is at level 0
        level = 0

        # This bootstraps the process by creating the right most child manifest
        # We call it `root` as it is, for now, the top-most manifest node.
        root_return_value = self._leaf_manifest(segment=segment, level=level)

        # Keep building subtrees until we're out of direct pointers
        while not segment.empty():
            level += 1
            root_return_value = self._bottom_up_preorder(segment=segment, level=level, right_most_child=root_return_value)

        return root_return_value.packet

    @staticmethod
    def _debug_packet(packet):
        name = packet.body().name()
        if name is not None:
            name = str(name)
        print(f"packet: {packet.content_object_hash()}, {name}")

    def _get_height(self, level):
        return self._params.tree_height() - level

    def _get_next_manifest_name(self, level) -> Name:
        """
        We assign unique IDs per level.  because we always go right-to-left at each level,
        we can use a sequence number per level.  At height h of the tree, the IDs are
        `range((k^n-1)/(k-1), (k^(n+1)-1)/(k-1))`, where k is `max_direct_per_node`.

        The tree height is the total height minus the level.
        """

        manifest_id = self._manifest_id_factory.get_next_id(height=self._get_height(level))
        if manifest_id < 0:
            raise ValueError(f"Created negative chunk id for manifest #{self._manifest_count}")
        self._manifest_count += 1
        self._last_manifest_id = manifest_id
        return self._name_ctx.manifest_schema_impl.get_name(manifest_id)

    def _write_packet(self, packet):
        if self._tree_options.debug:
            self._debug_packet(packet)

        if self._packet_output is not None:
            self._packet_output.put(packet)

    def _bottom_up_preorder(self, segment, level: int, right_most_child: ReturnValue = None) -> ReturnValue:
        """

        :param segment:
        :param level: The distance above the bottom-right-child's level
        :param right_most_child: a ccnpy.Packet
        :return: A ccnpy.Packet containing the root manifest of this subtree
        """
        if level == 0:
            assert right_most_child is None
            # build a leaf manifest with only direct pointers
            return self._leaf_manifest(segment=segment, level=level)
        else:
            # If the number of remaining direct pointers will fit in a leaf node, make one of those.
            # Otherwise, we need to be an interior node
            if right_most_child is None and segment.length() <= self._params.num_pointers_per_node():
                return self._leaf_manifest(segment=segment, level=level)
            else:
                return self._interior_manifest(segment=segment, level=level, right_most_child=right_most_child)

    def _get_start_segment_id(self, head: int) -> Optional[StartSegmentId]:
        if self._name_ctx.manifest_schema_impl.uses_name_id():
            return StartSegmentId(self._file_metadata[head].chunk_number)
        else:
            return None

    def _build_leaf_packet(self, head: int, tail: int, level: int):
        """
        A leaf packet is a direct-pointer only manifest.  That is, it has no sub-manifests.
        """
        assert tail > head
        count = tail - head
        builder = HashGroupBuilder(max_direct=count, max_indirect=0)
        for i in range(head, tail):
            chunk_metadata = self._file_metadata[i]
            builder.append_direct(hash_value=chunk_metadata.content_object_hash, leaf_size=chunk_metadata.payload_bytes)

        hg = builder.hash_group(include_leaf_size=self._tree_options.add_group_leaf_size,
                                include_subtree_size=self._tree_options.add_group_subtree_size,
                                start_segment_id=self._get_start_segment_id(head),
                                # These are all direct pointers, so they are in the data hash group
                                nc_id=self._name_ctx.data_schema_impl.nc_id())

        if self._tree_options.add_node_subtree_size:
            # obviously, indirect size should be 0 as we only called append_direct
            node_size = builder.direct_size() + builder.indirect_size()
            node_data = NodeData(subtree_size=node_size)
        else:
            node_data = None

        node = Node(node_data=node_data, hash_groups=[hg])
        manifest = self._factory.build(node)
        packet = manifest.packet(self._get_next_manifest_name(level), expiry_time=self._tree_options.manifest_expiry_time)
        return_value = TreeBuilder.ReturnValue(packet=packet, manifest=manifest, node=node)
        self._leaf_count += 1
        return return_value

    def _leaf_manifest(self, segment: Segment, level: int):
        count = self._params.num_pointers_per_node()
        # At most count items, but never go before the head
        start = max(segment.head(), segment.tail() - count)
        return_value = self._build_leaf_packet(head=start, tail=segment.tail(), level=level)

        segment.decrement_tail(segment.tail() - start)
        if self._tree_options.debug:
            print("leaf_manifest: %r" % return_value)

        self._write_packet(return_value.packet)
        return return_value

    def _interior_add_right_most_child(self, builders: HashGroupBuilderPair, right_most_child: ReturnValue):
        if right_most_child is not None:
            builders.append_indirect(hash_value=right_most_child.packet.content_object_hash(),
                                     subtree_size=self._get_optional_subtree_size(right_most_child.node.node_data()))

    def _interior_add_indirect(self, builders: HashGroupBuilderPair, segment, level: int):
        # Reserve space at the head of the segment for this node's direct pointers before
        # descending to children.  We want the top of the tree packed.
        reserve_count = min(self._params.internal_direct_per_node(), segment.length())
        segment.increment_head(reserve_count)

        while not builders.is_indirect_full() and not segment.empty():
            child = self._bottom_up_preorder(segment, level - 1)
            builders.prepend_indirect(hash_value=child.packet.content_object_hash(),
                                      subtree_size=self._get_optional_subtree_size(child.node.node_data()))

        # Pull back our reservation and put those pointers in our direct children
        segment.decrement_head(reserve_count)

    def _interior_add_direct(self, builders: HashGroupBuilderPair, segment) -> Optional[StartSegmentId]:
        least_chunk_id = None
        while not builders.is_direct_full() and not segment.empty():
            chunk_metadata = self._file_metadata[segment.tail() - 1]
            least_chunk_id = chunk_metadata.chunk_number
            builders.prepend_direct(chunk_metadata.content_object_hash, chunk_metadata.payload_bytes)
            segment.decrement_tail()

        if least_chunk_id is not None:
            return StartSegmentId(least_chunk_id)
        # we did not execute the while loop
        return None

    def _interior_packet(self,
                         builders: HashGroupBuilderPair,
                         direct_start_segment_id: Optional[StartSegmentId],
                         level: int) -> ReturnValue:

        if not self._name_ctx.manifest_schema_impl.uses_name_id():
            indirect_start_segment_id = None
        else:
            indirect_start_segment_id = StartSegmentId(self._last_manifest_id)

        if not self._name_ctx.data_schema_impl.uses_name_id():
            direct_start_segment_id = None

        hgs = builders.hash_groups(include_leaf_size=self._tree_options.add_group_leaf_size,
                                   include_subtree_size=self._tree_options.add_group_subtree_size,
                                   direct_start_segment_id=direct_start_segment_id,
                                   indirect_start_segment_id=indirect_start_segment_id)

        if self._tree_options.add_node_subtree_size:
            node_size = builders.direct_size() + builders.indirect_size()
            node_data = NodeData(subtree_size=node_size)
        else:
            node_data = None

        node = Node(node_data=node_data, hash_groups=hgs)
        manifest = self._factory.build(node)
        packet = manifest.packet(name=self._get_next_manifest_name(level), expiry_time=self._tree_options.manifest_expiry_time)
        return_value = TreeBuilder.ReturnValue(packet=packet, manifest=manifest, node=node)
        return return_value

    def _interior_manifest(self, segment, level: int, right_most_child: ReturnValue = None) -> ReturnValue:
        builders = HashGroupBuilderPair(name_ctx=self._name_ctx,
                                        max_direct=self._params.internal_direct_per_node(),
                                        max_indirect=self._params.internal_indirect_per_node())

        self._interior_add_right_most_child(builders, right_most_child)
        self._interior_add_indirect(builders, segment, level)
        direct_start_segment_id = self._interior_add_direct(builders, segment)

        return_value = self._interior_packet(builders=builders,
                                             direct_start_segment_id=direct_start_segment_id,
                                             level=level)

        if self._tree_options.debug:
            print(f"node_manifest: {return_value}")

        self._write_packet(return_value.packet)
        self._internal_count += 1
        return return_value

    def _get_optional_subtree_size(self, node_data: NodeData):
        if self._tree_options.add_node_subtree_size:
            return node_data.subtree_size().size()
        else:
            return None
