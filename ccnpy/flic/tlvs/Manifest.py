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

import array

from ccnpy.flic.tlvs.AuthTag import AuthTag
from .EncryptedNode import EncryptedNode
from .Node import Node
from .SecurityCtx import SecurityCtx
from ccnpy.core.ContentObject import ContentObject
from ccnpy.core.Packet import Packet
from ccnpy.core.Payload import Payload
from ccnpy.core.PayloadType import PayloadType
from ccnpy.core.Tlv import Tlv
from ...core.ExpiryTime import ExpiryTime
from ...core.Name import Name
from ...exceptions.ParseError import ParseError


class Manifest:
    """
    A Manifest is a ContentObject with PayloadType of Manifest.  The Payload
    is the set of TLVs (SecurityCtx? (EncryptedNode / Node) [AuthTag]).
    """

    @classmethod
    def from_content_object(cls, content_object: ContentObject):
        if not isinstance(content_object, ContentObject):
            raise TypeError("content_object must be ContentObject")
        if not content_object.payload_type().is_manifest():
            raise ValueError("Payload is not of type Manifest")

        try:
            return cls.deserialize(content_object.payload().value())
        except ParseError as e:
            print(f'Error parsing payload of content object: {e}')
            raise

    def __init__(self, security_ctx=None, node=None, auth_tag=None):
        """

        :param security_ctx: Optional context for an encrypted Node
        :param node: a Node or EncryptedNode
        :param auth_tag: Optional authentication tag for encrypted Node (e.g. AES-GCM MAC)
        """
        if node is None:
            raise ValueError("Node must be Node or EncryptedNode")

        self._security_ctx = security_ctx
        self._node = node
        self._auth_tag = auth_tag

        self._wire_format = array.array("B", [])
        if self._security_ctx is not None:
            self._wire_format.extend(self._security_ctx.serialize())
        self._wire_format.extend(self._node.serialize())
        if self._auth_tag is not None:
            self._wire_format.extend(self._auth_tag.serialize())

    def __repr__(self):
        return "Manifest: {%r, %r, %r}" % (self._security_ctx, self._node, self._auth_tag)

    def __eq__(self, other):
        if not isinstance(other, Manifest):
            return False
        return self._wire_format == other._wire_format

    def __len__(self):
        return len(self._wire_format)

    @classmethod
    def deserialize(cls, buffer):
        """
        Deserialize the byte array from a Content Object's Payload.
        :param buffer:
        :return:
        """
        offset = 0
        security_ctx = node = auth_tag = None
        while offset < len(buffer):
            tlv = Tlv.deserialize(buffer[offset:])
            if tlv.type() == SecurityCtx.class_type():
                assert security_ctx is None
                security_ctx = SecurityCtx.parse(tlv)
            elif tlv.type() == Node.class_type():
                assert node is None
                node = Node.parse(tlv)
            elif tlv.type() == EncryptedNode.class_type():
                assert node is None
                node = EncryptedNode.parse(tlv)
            elif tlv.type() == AuthTag.class_type():
                auth_tag = AuthTag.parse(tlv)
            else:
                raise ValueError("Unsupported TLV %r" % tlv)
            offset += len(tlv)

        return cls(security_ctx=security_ctx, node=node, auth_tag=auth_tag)

    def serialize(self):
        return self._wire_format

    def security_ctx(self):
        return self._security_ctx

    def node(self) -> Node:
        """

        :return: a Node or EncryptedNode
        """
        return self._node

    def auth_tag(self):
        return self._auth_tag

    def is_encrypted(self):
        return isinstance(self._node, EncryptedNode)

    def content_object(self, name: Name = None, expiry_time: ExpiryTime = None):
        co = ContentObject(name=name,
                           payload_type=PayloadType.create_manifest_type(),
                           payload=Payload(self.serialize()),
                           expiry_time=expiry_time)
        return co

    def packet(self, name=None, expiry_time=None):
        packet = Packet.create_content_object(body=self.content_object(name, expiry_time))
        return packet

    def hash_values(self) -> Node.NodeIterator:
        """
        An in-order list of pointer hashes from this Manifest's Node.

        :return: A list, may be empty
        """
        if not isinstance(self._node, Node):
            raise TypeError("Manifest Node is not supported type: %r" % self._node)

        return iter(self._node)

    def interest_list(self, locator=None, final=False):
        """
        Create a list of Interest for the contents of this manifest.  The list will
        be in traversal order.

        :return: A list of Interest, which may be empty
        """
        interests = []
        if not final:
            node_locator, node_final = self.node().locator()
            if node_locator is not None:
                locator = node_locator
                final = node_final

        hash_values = self.hash_values()
        raise RuntimeError("Not implemented")
