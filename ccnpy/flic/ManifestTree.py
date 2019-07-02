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

import ccnpy
from ccnpy.flic import ManifestFactory, ManifestTreeOptions
from ccnpy.flic.tree import FileChunks, TreeParameters, TreeBuilder


class ManifestTree:
    """
    Builds a manifest tree.
    """
    def __init__(self, data_input, packet_output, root_manifest_name, root_manifest_signer,
                 max_packet_size=1500, tree_options=None):
        """
        TODO: Need a better way to represent all the options and a way to communicate them to TreeBuilder.

        :param data_input: Something we can call read() on that returns byte arrays, e.g. open(filename, 'rb')
        :param packet_output: Something we can call put(ccnpy.Packet) on to output packets (see .tree.TreeIO)
        :param root_manifest_name: the ccnpy.Name of the root manifest
        :param root_manifest_signer: The ccnpy.crypto.Signer with which to sign the root manifest
        :param max_packet_size: The maximum bytes for a nameless manifest or data content object
        :param tree_options: (optional) ManifestTree.TreeOptions.  If none, uses the default values.
        """
        if tree_options is None:
            tree_options = ManifestTreeOptions()

        self._data_input = data_input
        self._packet_output = packet_output
        self._root_manifest_name = root_manifest_name
        self._root_manifest_signer = root_manifest_signer
        self._max_packet_size = max_packet_size
        self._tree_options = tree_options
        self._file_chunks = FileChunks()

    def build(self):
        """
        Builds the manifest tree, saving CCNx Packets to the packet_output.

        :return: The root_manifest packet, which is the named and signed manifest
        """
        total_file_bytes = self._chunk_input()

        manifest_factory = ManifestFactory(encryptor=self._tree_options.manifest_encryptor,
                                           tree_options=self._tree_options)

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
        ptr = ccnpy.flic.Pointers([top_nameless_packet.content_object_hash()])
        root_manifest = manifest_factory.build(source=ptr,
                                               node_locators=self._tree_options.root_locators,
                                               node_subtree_size=total_file_bytes,
                                               group_subtree_size=total_file_bytes)

        body = ccnpy.ContentObject.create_manifest(manifest=root_manifest,
                                                   name=self._root_manifest_name,
                                                   expiry_time=self._tree_options.root_expiry_time)

        validation_alg = self._root_manifest_signer.validation_alg()
        validation_payload = self._root_manifest_signer.sign(body.serialize(), validation_alg.serialize())

        root_packet = ccnpy.Packet.create_signed_content_object(body, validation_alg, validation_payload)
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

    def _calculate_nameless_data_payload_size(self):
        """
        Create a nameless object with empty payload and see how much space we have left.
        :return: payload size of a nameless data object
        """
        nameless = ccnpy.ContentObject.create_data(name=None,
                                                   expiry_time=self._tree_options.data_expiry_time,
                                                   payload=ccnpy.Payload([]))
        packet = ccnpy.Packet.create_content_object(body=nameless)
        if len(packet) >= self._max_packet_size:
            raise ValueError("An empty nameless ContentObject is %r bytes, but max_size is only %r" %
                             (len(packet), self._max_packet_size))

        payload_size = self._max_packet_size - len(packet)
        return payload_size

    def _chunk_input(self):
        total_file_bytes = 0
        payload_size = self._calculate_nameless_data_payload_size()

        payload_value = self._data_input.read(payload_size)
        while len(payload_value) > 0:
            total_file_bytes += len(payload_value)
            packet = self._create_nameless_data_packet(payload_value)
            self._cache_file_chunk(packet, len(payload_value))
            self._packet_output.put(packet)
            # read next payload and loop
            payload_value = self._data_input.read(payload_size)

        return total_file_bytes

    def _create_nameless_data_packet(self, payload_value):
        payload_tlv = ccnpy.Payload(payload_value)
        nameless = ccnpy.ContentObject.create_data(name=None,
                                                   payload=payload_tlv,
                                                   expiry_time=self._tree_options.data_expiry_time)
        packet = ccnpy.Packet.create_content_object(nameless)
        assert len(packet) <= self._max_packet_size
        return packet

    def _cache_file_chunk(self, packet, payload_length):
        co_hash = packet.content_object_hash()
        direct_pointer = ccnpy.flic.tree.SizedPointer(content_object_hash=co_hash, length=payload_length)
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

