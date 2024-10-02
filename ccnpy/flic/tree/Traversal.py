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
from ..Manifest import Manifest
from ..ManifestDecryptor import ManifestDecryptor
from ...core.ContentObject import ContentObject
from ...core.Packet import Packet


class Traversal:
    def __init__(self, packet_input, data_buffer, decryptor=None, debug=False):
        """
        :param decryptor: A concrete implementation of ManifestDecryptor.
        :param packet_input: AAn object with a 'get(hash_value)' method.
        :param data_buffer: The output buffer of the application data.  It must have an `append(array)` method.
        """
        if decryptor is not None and not issubclass(decryptor.__class__, ManifestDecryptor):
            raise TypeError("decryptor, if present, must subclass ccnpy.flic.ManifestDecryptor")

        self._decryptor = decryptor
        self._packet_input = packet_input
        self._data_buffer = data_buffer
        self._count = 0
        self.debug = debug

    def reset_count(self):
        self._count = 0

    def count(self):
        return self._count

    def preorder(self, packet):
        """
        Pre-order traversal of a Manifest tree.  The packet may be a Data content object
        or a Manifest content object.  If it is Data, the payload is appended to the data_buffer array.

        :param packet: A ccnpy.Packet.
        :return:
        """
        if not isinstance(packet, Packet):
            raise TypeError("node must be ccnpy.Packet")

        self._count += 1
        body = packet.body()
        if not isinstance(body, ContentObject):
            raise TypeError("body of the packet must be ccnpy.ContentObject")

        if body.payload_type().is_manifest():
            manifest = self._manifest_from_content_object(body)
            if self.debug:
                print("Traversal: %r" % manifest)

            self._visit_children(manifest)
        elif body.payload_type().is_data():
            if self.debug:
                print("Traversal: %r" % body)
            self._write_data(body.payload())

        else:
            raise ValueError("Unsupported payload type: %r" % body)

    def _write_data(self, payload):
        if self._data_buffer is not None:
            self._data_buffer.append(payload.value())

    def _visit_children(self, manifest):
        """
        A child may be a direct pointer to local data or an indirect pointer to another
        manifest.  In the pre-order traversal, we do not distinguish (nor can we) between these.
        Our commitment is to visit all children in order.

        :param manifest:
        :return:
        """
        hash_values = manifest.hash_values()
        for hv in hash_values:
            packet = self._packet_input.get(hv)
            if packet is None:
                raise ValueError("Failed to get packet for: %r" % hv)
            self.preorder(packet)

    def _manifest_from_content_object(self, content_object):
        manifest = Manifest.from_content_object(content_object)
        if manifest.is_encrypted():
            if self._decryptor is None:
                raise RuntimeError("Manifest is encrypted, but decryptor is None")

            manifest = self._decryptor.decrypt_manifest(manifest)

        return manifest
