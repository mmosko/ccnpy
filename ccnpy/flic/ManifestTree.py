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

from .ManifestFactory import ManifestFactory
from .ManifestTreeOptions import ManifestTreeOptions
from .name_constructor.FileMetadata import FileMetadata
from .name_constructor.NameConstructorContext import NameConstructorContext
from .tlvs.Pointers import Pointers
from .tlvs.StartSegmentId import StartSegmentId
from .tree.ManifestGraph import ManifestGraph
from .tree.TreeBuilder import TreeBuilder
from .tree.TreeParameters import TreeParameters
from ..core.Packet import Packet, PacketWriter


class ManifestTree:
    """
    Builds a manifest tree.
    """

    def __init__(self, data_input, packet_output: PacketWriter, tree_options: ManifestTreeOptions,
                 manifest_graph: Optional[ManifestGraph] = None,
                 name_context: Optional[NameConstructorContext] = None):
        """
        The `tree_options` must specify the name and schema.  Creates an optimized manifest tree, packing some data
        into the internal nodes.  it will minimize the tree height within the `tree_options.max_tree_degree`.

        If `tree_options.max_tree_degree` is not given, it will pick a degree that minimizes the wasted space
        in the tree.

        :param data_input: Something we can call read() on, or a FileMetadata
        :param packet_output: Something we can call put(ccnpy.Packet) on to output packets (see .tree.TreeIO)
        :param tree_options:
        :param manifest_graph: If not None, will be filled in as we build the tree
        """
        self._packet_output = packet_output
        self._tree_options = tree_options
        self._name_ctx = name_context if name_context is not None else NameConstructorContext.create(self._tree_options)
        self._manifest_graph = manifest_graph
        if isinstance(data_input, FileMetadata):
            self._file_metadata = data_input
        else:
            self._file_metadata = self._name_ctx.data_schema_impl.chunk_data(data_input, self._packet_output)
        self._manifest_factory = ManifestFactory(tree_options=self._tree_options, manifest_graph=self._manifest_graph)
        self._optimized_params = self._calculate_optimal_tree(file_metadata=self._file_metadata, manifest_factory=self._manifest_factory)
        # print(f"Optimized parameters: {self._optimized_params}")

    def name_context(self):
        return self._name_ctx

    def build(self) -> Packet:
        """
        Builds the manifest tree, saving CCNx Packets to the packet_output.

        :return: The root_manifest packet, which is the named and signed manifest
        """
        #if self._tree_options.debug:
        print(f"Optimized parameters: {self._optimized_params}")

        top_manifest_packet = self.build_top()
        root_packet = self.build_root(top_manifest_packet=top_manifest_packet)

        print(f"Manifest count {self._manifest_factory.cnt_manifests}, bytes {self._manifest_factory.cnt_manifest_bytes}")
        return root_packet

    def build_top(self) -> Packet:
        top_manifest_packet = self._build_tree(tree_parameters=self._optimized_params,
                                               manifest_factory=self._manifest_factory,
                                               file_metadata=self._file_metadata)
        # print(f"Manifest count {self._manifest_factory.cnt_manifests}, bytes {self._manifest_factory.cnt_manifest_bytes}")
        return top_manifest_packet

    def build_root(self, top_manifest_packet: Packet) -> Packet:
        root_packet = self._create_root_manifest(top_manifest_packet=top_manifest_packet,
                                                 manifest_factory=self._manifest_factory,
                                                 total_file_bytes=self._file_metadata.total_bytes)
        self._packet_output.put(root_packet)
        return root_packet

    def _create_root_manifest(self, manifest_factory: ManifestFactory, total_file_bytes, top_manifest_packet: Packet):
        """
        The root manifest has a CCNx Name and public key signature.  It is a manifest with one pointer to the
        top manifest packet.

        The root manifest has the name constructor definitions (`nc_defs`)

        :param top_manifest_packet: ccnpy.Packet with the top-level manifest
        :param manifest_factory: The factory to use to create manifests
        :return:
        """
        ptr = Pointers([top_manifest_packet.content_object_hash()])

        # if the top manifest is SegmentedSchema, we need to include the fact that the chunk_id is 0
        if self._name_ctx.manifest_schema_impl.uses_name_id():
            start_segment_id=StartSegmentId(0)
        else:
            start_segment_id=None

        root_packet = manifest_factory.build_packet(
            source=ptr,
            nc_defs=self._name_ctx.nc_def(),
            node_subtree_size=total_file_bytes,
            group_subtree_size=total_file_bytes,
            nc_id=self._name_ctx.manifest_schema_impl.nc_id(),
            start_segment_id=start_segment_id,
            name=self._tree_options.name,
            expiry_time=self._tree_options.root_expiry_time,
            signer=self._tree_options.signer,
            include_full_security_context=True)

        if self._tree_options.debug:
            print(f"Root packet: {root_packet}")

        if len(root_packet) > self._tree_options.max_packet_size:
            # should be logged as a warning?  This only really happens when we set a small MTU in
            # unit tests.
            print(ValueError(f'The root manifest packet is {len(root_packet)} bytes, greater than max_packet_size {self._tree_options.max_packet_size}'))
        return root_packet

    def _build_tree(self, tree_parameters: TreeParameters, manifest_factory: ManifestFactory, file_metadata: FileMetadata) -> Packet:
        tree_builder = TreeBuilder(file_metadata=file_metadata,
                                   tree_parameters=tree_parameters,
                                   manifest_factory=manifest_factory,
                                   packet_output=self._packet_output,
                                   tree_options=self._tree_options,
                                   name_ctx=self._name_ctx,
                                   manifest_graph=self._manifest_graph)
        return tree_builder.build()

    def _calculate_optimal_tree(self, file_metadata: FileMetadata, manifest_factory: ManifestFactory) -> TreeParameters:
        if self._manifest_graph is not None:
            self._manifest_graph.pause()
        optimized_params = TreeParameters.create_optimized_tree(file_metadata=file_metadata,
                                                                manifest_factory=manifest_factory,
                                                                name_ctx=self._name_ctx)
        if self._manifest_graph is not None:
            self._manifest_graph.resume()
        return optimized_params
