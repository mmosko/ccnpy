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
from ccnpy.flic.tlvs.Pointers import Pointers
from .name_constructor.FileMetadata import FileMetadata
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import HashSchema
from .name_constructor.SchemaImplFactory import SchemaImplFactory
from .tree.TreeBuilder import TreeBuilder
from .tree.TreeParameters import TreeParameters
from ..core.ContentObject import ContentObject
from ..core.Packet import Packet, PacketWriter


class LeafOnlyManifestTree:
    """
    Builds a manifest tree.
    """

    def __init__(self, data_input: BinaryIO, packet_output: PacketWriter, tree_options: ManifestTreeOptions):
        """
        The `LeafOnlyManifestTree` only stores data at the leaf nodes.  It is provided as an example of
        a simpler tree construction than the `ManifestTree`.  The leaf only tree is built from the
        top-down.

        It will pick the largest tree degree that fits in a max_packet_size, but will not exceed
        `tree_options.max_tree_degree`.

        :param data_input: Something we can call read() on that returns byte arrays, e.g. open(filename, 'rb')
        :param packet_output: Something we can call put(ccnpy.Packet) on to output packets (see .tree.TreeIO)
        :param tree_options:
        """
        self._data_input = data_input
        self._packet_output = packet_output
        self._tree_options = tree_options

        nc_id = NcId(0)
        schema = HashSchema(locators=tree_options.manifest_locators)
        self._nc_impl = SchemaImplFactory.create(nc_id=nc_id, schema=schema, tree_options=tree_options)

    def build(self) -> Packet:
        """
        Builds the manifest tree, saving CCNx Packets to the packet_output.

        :return: The root_manifest packet, which is the named and signed manifest
        """

        file_metadata = self._nc_impl.chunk_data(self._data_input, self._packet_output)
        manifest_factory = ManifestFactory(tree_options=self._tree_options)
        optimized_params = self._calculate_optimal_tree(file_metadata=file_metadata, manifest_factory=manifest_factory)

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

        :param top_manifest_packet: ccnpy.Packet with the top-level manifest
        :param manifest_factory: The factory to use to create manifests
        :return:
        """
        ptr = Pointers([top_manifest_packet.content_object_hash()])
        root_manifest = manifest_factory.build(source=ptr,
                                               node_locators=self._tree_options.manifest_locators,
                                               node_subtree_size=total_file_bytes,
                                               group_subtree_size=total_file_bytes)

        body = ContentObject.create_manifest(manifest=root_manifest,
                                             name=self._tree_options.name,
                                             expiry_time=self._tree_options.root_expiry_time)

        validation_alg = self._tree_options.signer.validation_alg()
        validation_payload = self._tree_options.signer.sign(body.serialize(), validation_alg.serialize())

        root_packet = Packet.create_signed_content_object(body, validation_alg, validation_payload)
        return root_packet

    def _build_tree(self, tree_parameters: TreeParameters, manifest_factory: ManifestFactory, file_metadata: FileMetadata) -> Packet:
        tree_builder = TreeBuilder(file_metadata=file_metadata,
                                   tree_parameters=tree_parameters,
                                   manifest_factory=manifest_factory,
                                   packet_output=self._packet_output,
                                   tree_options=self._tree_options)
        return tree_builder.build()

    def _calculate_optimal_tree(self, file_metadata: FileMetadata, manifest_factory: ManifestFactory) -> TreeParameters:
        optimized_params = TreeParameters.create_optimized_tree(file_metadata=file_metadata,
                                                                max_packet_size=self._tree_options.max_packet_size,
                                                                max_tree_degree=self._tree_options.max_tree_degree,
                                                                manifest_factory=manifest_factory)
        return optimized_params
