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
import logging
from typing import Optional, Dict, List

from .DecryptorCache import DecryptorCache
from .ManifestGraph import ManifestGraph
from ..name_constructor.SchemaImpl import SchemaImpl
from ..name_constructor.SchemaImplFactory import SchemaImplFactory
from ..tlvs.AeadCtx import AeadCtx
from ..tlvs.Manifest import Manifest
from ..tlvs.NcDef import NcDef
from ..tlvs.RsaOaepCtx import RsaOaepCtx
from ...core.ContentObject import ContentObject
from ...core.DisplayFormatter import DisplayFormatter
from ...core.HashValue import HashValue
from ...core.Name import Name
from ...core.Packet import Packet, PacketReader
from ...core.PacketValidator import PacketValidator
from ...crypto.InsecureKeystore import InsecureKeystore


class Traversal:
    """
    Walks a FLIC manifest in the traversal order.
    """
    logger = logging.getLogger(__name__)

    class NameConstructorCache:
        _next_cache_id = 1
        def __init__(self, copy: Dict[int, SchemaImpl]=None):
            self._cache_id = Traversal.NameConstructorCache._next_cache_id
            Traversal.NameConstructorCache._next_cache_id += 1

            if copy is not None:
                self.cache = copy.copy()
            else:
                self.cache: Dict[int, SchemaImpl] = {}

        def update(self, nc_defs: List[NcDef]):
            for nc_def in nc_defs:
                print(f'NcCache[inst={self._cache_id}][ncid={nc_def.nc_id().id()}] = {nc_def.schema()}')
                self.cache[nc_def.nc_id().id()] = SchemaImplFactory.from_ncdef(nc_def)

    def __init__(self, packet_input: PacketReader, data_writer, keystore: Optional[InsecureKeystore] = None,
                 build_graph: bool = False):
        """
        :param packet_input: A reader that we can fetch objects from via '.get'
        :param data_writer: A writer we can append application data to for output (needs to support `.write(bytes)`).
        :param kestore: Used to verify packets and decrypt manifests (if none, no packet verification or decryption)
        """
        self._packet_input = packet_input
        self._data_writer = data_writer
        self._keystore = keystore
        self._count = 0
        self._validator = PacketValidator(keystore=self._keystore)
        self._decryptor_cache = DecryptorCache(self._keystore)
        self._build_graph = build_graph
        self._manifest_graph = ManifestGraph()

    def get_graph(self):
        """Will only be built if `build_graph` is true in construfctor"""
        return self._manifest_graph

    def reset_count(self):
        self._count = 0

    def count(self):
        return self._count

    def traverse(self, root_name: Name, hash_restriction: Optional[HashValue] = None):
        """
        Traverse the manifest rooted at `name`.
        """
        nc_cache = Traversal.NameConstructorCache()
        root_packet = self._packet_input.get(name=root_name, hash_restriction=hash_restriction)
        self.logger.debug('Traversal root packet: %s', root_packet)

        self._validator.validate_packet(packet=root_packet)
        self.preorder(packet=root_packet, nc_cache=nc_cache)

    def preorder(self, packet: Packet, nc_cache: Optional[NameConstructorCache] = None):
        """
        Pre-order traversal of a Manifest tree.  The packet may be a Data content object
        or a Manifest content object.  If it is Data, the payload is appended to the data_buffer array.

        :param packet: A ccnpy.Packet.
        :param nc_cache: The name constructor cache.  It may be modified as we traverse down branches.
        :return:
        """
        self.logger.debug('Preorder %s => %s', packet.content_object_hash(), packet)

        if nc_cache is None:
            nc_cache = Traversal.NameConstructorCache()

        if not isinstance(packet, Packet):
            raise TypeError("node must be ccnpy.Packet")

        self._count += 1
        body = packet.body()
        if not isinstance(body, ContentObject):
            raise TypeError("body of the packet must be ccnpy.ContentObject")

        if body.payload_type().is_manifest():
            manifest = self._manifest_from_content_object(body)
            if self._build_graph:
                self._manifest_graph.add_manifest(hash_value=packet.content_object_hash(), node=manifest.node(), name=packet.body().name())

            self.logger.debug("Preorder: %s", manifest)

            nc_cache = self._update_nc_cache(nc_cache=nc_cache, manifest=manifest)
            try:
                self._visit_children(parent_packet=packet, manifest=manifest, nc_cache=nc_cache)
            except Exception as e:
                print(f'Error {e} processing {manifest}')
                raise

        elif body.payload_type().is_data():
            self.logger.debug("Traversal: %s", body)

            if self._build_graph:
                self._manifest_graph.add_data(data_hash=packet.content_object_hash(), name=packet.body().name())

            self._write_data(body.payload())

        else:
            raise ValueError("Unsupported payload type: %r" % body)

    def _write_data(self, payload):
        if self._data_writer is not None:
            self.logger.debug('Traversal save %d bytes', len(payload.value()))
            self._data_writer.write(payload.value())

    def _visit_children(self, parent_packet: Packet, manifest: Manifest, nc_cache: NameConstructorCache):
        """
        A child may be a direct pointer to local data or an indirect pointer to another
        manifest.  In the pre-order traversal, we do not distinguish (nor can we) between these.
        Our commitment is to visit all children in order.

        :param manifest:
        :param nc_cache: name constructor cache for the current branch
        :return:
        """
        children = []
        for hash_iterator_value in manifest.hash_values():
            if self.logger.isEnabledFor(logging.DEBUG):
                children.append(DisplayFormatter.hexlify(hash_iterator_value.hash_value.value()))

            packet = self._fetch_packet(nc_cache=nc_cache,
                                        nc_id=hash_iterator_value.nc_id,
                                        hash_value=hash_iterator_value.hash_value,
                                        segment_id=hash_iterator_value.segment_id)
            if packet is None:
                raise ValueError("Failed to get packet for: %r" % hash_iterator_value)

            self.logger.debug('visit_children: child %s', packet)

            self._validator.validate_packet(packet=packet)
            self.preorder(packet=packet, nc_cache=nc_cache)

        if self.logger.isEnabledFor(logging.DEBUG):
            packet_id = DisplayFormatter.hexlify(parent_packet.content_object_hash().value())
            self.logger.debug('parent %s : children: %s', packet_id, children)

    def _manifest_from_content_object(self, content_object):
        manifest = Manifest.from_content_object(content_object)
        return self._decrypt(manifest)

    def _decrypt(self, manifest: Manifest) -> Manifest:
        if not manifest.is_encrypted():
            return manifest

        security_ctx = manifest.security_ctx()
        if isinstance(security_ctx, AeadCtx):
            decryptor = self._decryptor_cache.get_or_create(security_ctx)
            # may raise DecryptionError
        elif isinstance(security_ctx, RsaOaepCtx):
            decryptor = self._decryptor_cache.get_or_create(security_ctx)
        else:
            raise ValueError(f"Unsupported encryption mode: {security_ctx}")
        return decryptor.decrypt_manifest(manifest)

    @staticmethod
    def _update_nc_cache(nc_cache: NameConstructorCache, manifest: Manifest):
        """
        If the NodeData has name constructor updates, make a new cache with the updates.  If there's no
        NcDefs, we can continue using the current cache.

        We need to make a new cache because those updates only apply to the branch we are on, not our
        parent or siblings.
        """
        if manifest.node().has_node_data():
            nc_defs = manifest.node().node_data().nc_defs()
            if nc_defs is not None and len(nc_defs) > 0:
                new_cache = Traversal.NameConstructorCache(copy=nc_cache.cache)
                new_cache.update(nc_defs)
                return new_cache
        return nc_cache

    def _fetch_packet(self, nc_cache: NameConstructorCache, nc_id: int, hash_value: HashValue, segment_id: Optional[int]):
        schema_impl = nc_cache.cache[nc_id]
        interest_name = schema_impl.get_name(segment_id)
        self.logger.debug('fetch_packet: %s, %s', interest_name, hash_value)
        return self._packet_input.get(name=interest_name, hash_restriction=hash_value)
