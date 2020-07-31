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

import ccnpy.flic.tree
from ccnpy.flic import ManifestTreeOptions


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

    # class Node:
    #     def __init__(self, children):
    #         self.children = children
    #
    #     def __repr__(self):
    #         return "{Node %r}" % self.children

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
            return "{Segment %r, %r}" % (self._head, self._tail, )

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

    def __init__(self, file_chunks, tree_parameters, manifest_factory, packet_output, tree_options=None):
        """

        :param direct_pointers: An in-order list of direct pointers (first byte to last byte)
        :param tree_parameters:
        :param manifest_factory: ccnpy.flic.ManifestFactory
        :param packet_output: A class that has a `put(packet)` method
        :param expiry_time: Optional expiry time to apply to all Manifest Content Objects.
        """
        if not isinstance(tree_parameters, ccnpy.flic.tree.TreeParameters):
            raise TypeError("tree_parameters must be ccnpy.flic.tree.TreeParameters")

        if not isinstance(file_chunks, ccnpy.flic.tree.FileChunks):
            raise TypeError("file_chunks must be ccnpy.flic.tree.FileChunks")

        if not isinstance(manifest_factory, ccnpy.flic.ManifestFactory):
            raise TypeError("manifest_factory must be ccnpy.flic.ManifestFactory")

        if tree_options is None:
            tree_options = ManifestTreeOptions()

        self._file_chunks = file_chunks
        self._params = tree_parameters
        self._factory = manifest_factory
        self._tree_options = tree_options
        self._packet_output = packet_output

    def build(self):
        """

        :return: The root ccnpy.Packet
        """
        segment = TreeBuilder.Segment(0, len(self._file_chunks))
        level = 0

        # This bootstraps the process by creating the right most child manifest
        root = self._leaf_manifest(segment=segment)

        # Keep building subtrees until we're out of direct pointers
        while not segment.empty():
            level += 1
            root = self._bottom_up_preorder(segment=segment, level=level, right_most_child=root)

        return root.packet

    def _write_packet(self, packet):
        if self._packet_output is not None:
            self._packet_output.put(packet)

    def _bottom_up_preorder(self, segment, level, right_most_child=None):
        """

        :param segment:
        :param level:
        :param right_most_child: a ccnpy.Packet
        :return: A ccnpy.Packet containing the root manifest of this subtree
        """
        return_value = None
        if level == 0:
            assert right_most_child is None
            # build a leaf manifest with only direct pointers
            return_value = self._leaf_manifest(segment=segment)
        else:
            # If the number of remaining direct pointers will fit in a leaf node, make one of those.
            # Otherwise, we need to be an interior node
            if right_most_child is None and segment.length() <= self._params.num_pointers_per_node():
                return_value = self._leaf_manifest(segment=segment)
            else:
                return_value = self._interior_manifest(segment=segment, level=level, right_most_child=right_most_child)

        return return_value

    def _build_leaf_packet(self, head, tail):
        assert tail > head
        count = tail - head
        builder = ccnpy.flic.HashGroupBuilder(max_direct=count, max_indirect=0)
        for i in range(head, tail):
            ptr = self._file_chunks[i]
            builder.append_direct(hash_value=ptr.content_object_hash(), leaf_size=ptr.length())

        hg = builder.hash_group(include_leaf_size=self._tree_options.add_group_leaf_size,
                                include_subtree_size=self._tree_options.add_group_subtree_size)

        if self._tree_options.add_node_subtree_size:
            node_size = builder.direct_size()
            node_data = ccnpy.flic.NodeData(subtree_size=node_size)
        else:
            node_data = None

        node = ccnpy.flic.Node(node_data=node_data, hash_groups=[hg])
        manifest = self._factory.build(node)
        packet = manifest.packet(expiry_time=self._tree_options.manifest_expiry_time)
        return_value = TreeBuilder.ReturnValue(packet=packet, manifest=manifest, node=node)
        return return_value

    def _leaf_manifest(self, segment):
        count = self._params.num_pointers_per_node()
        # At most count items, but never go before the head
        start = max(segment.head(), segment.tail() - count)
        return_value = self._build_leaf_packet(head=start, tail=segment.tail())

        segment.decrement_tail(segment.tail() - start)
        if self._tree_options.debug:
            print("leaf_manifest: %r" % return_value)

        self._write_packet(return_value.packet)
        return return_value

    def _interior_add_right_most_child(self, builder, right_most_child):
        if right_most_child is not None:
            if not isinstance(right_most_child, ccnpy.flic.tree.TreeBuilder.ReturnValue):
                raise TypeError("right_most_child must be ccnpy.flic.tree.TreeBuilder.ReturnValue")

            subtree_size = right_most_child.node.node_data().subtree_size()
            builder.append_indirect(hash_value=right_most_child.packet.content_object_hash(),
                                    subtree_size=subtree_size.size())

    def _interior_add_indirect(self, builder, segment, level):
        # Reserve space at the head of the segment for this node's direct pointers before
        # descending to children.  We want the top of the tree packed.
        reserve_count = min(self._params.internal_direct_per_node(), segment.length())
        segment.increment_head(reserve_count)

        while not builder.is_indirect_full() and not segment.empty():
            child = self._bottom_up_preorder(segment, level - 1)
            builder.prepend_indirect(hash_value=child.packet.content_object_hash(),
                                    subtree_size=child.node.node_data().subtree_size().size())

        # Pull back our reservation and put those pointers in our direct children
        segment.decrement_head(reserve_count)

    def _interior_add_direct(self, builder, segment):
        while not builder.is_direct_full() and not segment.empty():
            manifest_pointer = self._file_chunks[segment.tail() - 1]
            builder.prepend_direct(manifest_pointer.content_object_hash(), manifest_pointer.length())
            segment.decrement_tail()

    def _interior_packet(self, builder):
        hg = builder.hash_group(include_leaf_size=self._tree_options.add_group_leaf_size,
                                include_subtree_size=self._tree_options.add_group_subtree_size)

        if self._tree_options.add_node_subtree_size:
            node_size = builder.direct_size() + builder.indirect_size()
            node_data = ccnpy.flic.NodeData(subtree_size=node_size)
        else:
            node_data = None

        node = ccnpy.flic.Node(node_data=node_data, hash_groups=[hg])
        manifest = self._factory.build(node)
        packet = manifest.packet(expiry_time=self._tree_options.manifest_expiry_time)
        return_value = TreeBuilder.ReturnValue(packet=packet, manifest=manifest, node=node)
        return return_value

    def _interior_manifest(self, segment, level, right_most_child=None):
        builder = ccnpy.flic.HashGroupBuilder(max_direct=self._params.internal_direct_per_node(),
                                              max_indirect=self._params.internal_indirect_per_node())

        self._interior_add_right_most_child(builder, right_most_child)
        self._interior_add_indirect(builder, segment, level)
        self._interior_add_direct(builder, segment)

        return_value = self._interior_packet(builder)

        if self._tree_options.debug:
            print("node_manifest: %r" % return_value)

        self._write_packet(return_value.packet)
        return return_value
