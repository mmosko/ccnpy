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

from typing import BinaryIO

from .ManifestFactory import ManifestFactory
from .ManifestTreeOptions import ManifestTreeOptions
from .Pointers import Pointers
from .name_constructor.SchemaImplFactory import SchemaImplFactory
from .tree.FileChunks import FileChunks
from .tree.SizedPointer import SizedPointer
from .tree.TreeBuilder import TreeBuilder
from .tree.TreeParameters import TreeParameters
from ..core.ContentObject import ContentObject
from ..core.Packet import Packet, PacketWriter


class ManifestTree:
    """
    Builds a manifest tree.
    """

    def __init__(self, data_input: BinaryIO, packet_output: PacketWriter, tree_options: ManifestTreeOptions):
        """
        The `tree_options` must specify the name and schema.

        :param data_input: Something we can call read() on that returns byte arrays, e.g. open(filename, 'rb')
        :param packet_output: Something we can call put(ccnpy.Packet) on to output packets (see .tree.TreeIO)
        :param tree_options: (optional) ManifestTree.TreeOptions.  If none, uses the default values.
        """
        self._data_input = data_input
        self._packet_output = packet_output
        self._tree_options = tree_options
        self._file_chunks = FileChunks()

    def build(self):
        """
        Builds the manifest tree, saving CCNx Packets to the packet_output.

        :return: The root_manifest packet, which is the named and signed manifest
        """

        impl = SchemaImplFactory.create(tree_options=self._tree_options)
        file_metadata = impl.chunk_data(self._data_input, self._packet_output)

        manifest_factory = ManifestFactory(tree_options=self._tree_options)

        optimized_params = self._calculate_optimal_tree(manifest_factory)

        top_nameless_packet = self._build_tree(tree_parameters=optimized_params,
                                               manifest_factory=manifest_factory)

        root_packet = self._create_root_manifest(top_nameless_packet=top_nameless_packet,
                                                 manifest_factory=manifest_factory,
                                                 total_file_bytes=total_file_bytes)
        return root_packet

    def _create_root_manifest(self, top_nameless_packet, manifest_factory, total_file_bytes):
        """
        The root manifest has a CCNx Name and public key signature.  It is a manifest with one pointer to the
        top nameless packet.

        :param top_nameless_packet: ccnpy.Packet with the top-level manifest
        :param manifest_factory: The factory to use to create manifests
        :return:
        """
        ptr = Pointers([top_nameless_packet.content_object_hash()])
        root_manifest = manifest_factory.build(source=ptr,
                                               node_locators=self._tree_options.root_locators,
                                               node_subtree_size=total_file_bytes,
                                               group_subtree_size=total_file_bytes)

        body = ContentObject.create_manifest(manifest=root_manifest,
                                             name=self._root_manifest_name,
                                             expiry_time=self._tree_options.root_expiry_time)

        validation_alg = self._root_manifest_signer.validation_alg()
        validation_payload = self._root_manifest_signer.sign(body.serialize(), validation_alg.serialize())

        root_packet = Packet.create_signed_content_object(body, validation_alg, validation_payload)
        self._packet_output.put(root_packet)

        return root_packet

    def _build_tree(self, tree_parameters, manifest_factory):
        tree_builder = TreeBuilder(file_chunks=self._file_chunks,
                                   tree_parameters=tree_parameters,
                                   manifest_factory=manifest_factory,
                                   packet_output=self._packet_output,
                                   tree_options=self._tree_options)
        return tree_builder.build()

    def _calculate_optimal_tree(self, manifest_factory):
        optimized_params = TreeParameters.create_optimized_tree(file_chunks=self._file_chunks,
                                                                max_packet_size=self._max_packet_size,
                                                                max_tree_degree=self._tree_options.max_tree_degree,
                                                                manifest_factory=manifest_factory)
        return optimized_params

    def _cache_file_chunk(self, packet, payload_length):
        co_hash = packet.content_object_hash()
        direct_pointer = SizedPointer(content_object_hash=co_hash, length=payload_length)
        self._file_chunks.append(direct_pointer)


class TreeOptions:
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
        :param manifest_encryptor: (optional) The ManifestEncryptor to encrypt manifests
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
