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

from .ManifestFactory import ManifestFactory
from .ManifestTreeOptions import ManifestTreeOptions
from .name_constructor.FileMetadata import FileMetadata
from .name_constructor.NameConstructorContext import NameConstructorContext
from .tlvs.Pointers import Pointers
from .tlvs.StartSegmentId import StartSegmentId
from .tree.TreeBuilder import TreeBuilder
from .tree.TreeParameters import TreeParameters
from ..core.Packet import Packet, PacketWriter


class ManifestTree:
    """
    Builds a manifest tree.
    """

    def __init__(self, data_input, packet_output: PacketWriter, tree_options: ManifestTreeOptions):
        """
        The `tree_options` must specify the name and schema.  Creates an optimized manifest tree, packing some data
        into the internal nodes.  it will minimize the tree height within the `tree_options.max_tree_degree`.

        If `tree_options.max_tree_degree` is not given, it will pick a degree that minimizes the wasted space
        in the tree.

        :param data_input: Something we can call read() on that returns byte arrays, e.g. open(filename, 'rb')
        :param packet_output: Something we can call put(ccnpy.Packet) on to output packets (see .tree.TreeIO)
        :param tree_options:
        """
        self._data_input = data_input
        self._packet_output = packet_output
        self._tree_options = tree_options
        self._name_ctx = NameConstructorContext.create(self._tree_options)

    def name_context(self):
        return self._name_ctx

    def build(self) -> Packet:
        """
        Builds the manifest tree, saving CCNx Packets to the packet_output.

        :return: The root_manifest packet, which is the named and signed manifest
        """

        file_metadata = self._name_ctx.data_schema_impl.chunk_data(self._data_input, self._packet_output)
        manifest_factory = ManifestFactory(tree_options=self._tree_options)
        optimized_params = self._calculate_optimal_tree(file_metadata=file_metadata,
                                                        manifest_factory=manifest_factory)

        if self._tree_options.debug:
            print(f"Optimized parameters: {optimized_params}")

        top_manifest_packet = self._build_tree(tree_parameters=optimized_params,
                                               manifest_factory=manifest_factory,
                                               file_metadata=file_metadata)

        root_packet = self._create_root_manifest(top_manifest_packet=top_manifest_packet,
                                                 manifest_factory=manifest_factory,
                                                 total_file_bytes=file_metadata.total_bytes)
        self._packet_output.put(root_packet)
        return root_packet

    def _create_root_manifest(self, top_manifest_packet: Packet, manifest_factory: ManifestFactory, total_file_bytes):
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
        if self._name_ctx.manifest_schema_impl.uses_final_chunk_id():
            start_segment_id=StartSegmentId(0)
        else:
            start_segment_id=None

        root_manifest = manifest_factory.build(source=ptr,
                                               nc_defs=self._name_ctx.nc_def(),
                                               node_subtree_size=total_file_bytes,
                                               group_subtree_size=total_file_bytes,
                                               nc_id=self._name_ctx.manifest_schema_impl.nc_id(),
                                               start_segment_id=start_segment_id)

        body = root_manifest.content_object(name=self._tree_options.name,
                                             expiry_time=self._tree_options.root_expiry_time)

        validation_alg = self._tree_options.signer.validation_alg()
        validation_payload = self._tree_options.signer.sign(body.serialize(), validation_alg.serialize())

        root_packet = Packet.create_signed_content_object(body, validation_alg, validation_payload)
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
                                   name_ctx=self._name_ctx)
        return tree_builder.build()

    def _calculate_optimal_tree(self, file_metadata: FileMetadata, manifest_factory: ManifestFactory) -> TreeParameters:
        optimized_params = TreeParameters.create_optimized_tree(file_metadata=file_metadata,
                                                                manifest_factory=manifest_factory,
                                                                name_ctx=self._name_ctx)
        return optimized_params
