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

import array
import ccnpy


class Manifest:
    """
    A Manifest is a ContentObject with PayloadType of Manifest.  The Payload
    is the set of TLVs (SecurityCtx? (EncryptedNode / Node)).
    """

    @classmethod
    def from_content_object(cls, content_object):
        if not isinstance(content_object, ccnpy.ContentObject):
            raise TypeError("content_object must be ccnpy.ContentObject")
        if not content_object.payload_type().is_manifest():
            raise ValueError("Payload is not of type Manifest")

        return cls.deserialize(content_object.payload())

    def __init__(self, security_ctx=None, node=None, auth_tag=None):
        """

        :param security_ctx: Optional context for an encrypted Node
        :param node: a ccnpy.flic.Node or ccnpy.flic.EncryptedNode
        :param auth_tag: Optional authentication tag for encrypted Node (e.g. AES-GCM MAC)
        """
        if node is None:
            raise ValueError("Node must be ccnpy.flic.Node or ccnpy.flic.EncryptedNode")

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
        return "Manifest(%r, %r, %r)" % (self._security_ctx, self._node, self._auth_tag)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

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
            tlv = ccnpy.Tlv.deserialize(buffer[offset:])
            if tlv.type() == ccnpy.flic.SecurityCtx.class_type():
                assert security_ctx is None
                security_ctx = ccnpy.flic.SecurityCtx.parse(tlv)
            elif tlv.type() == ccnpy.flic.Node.class_type():
                assert node is None
                node = ccnpy.flic.Node.parse(tlv)
            elif tlv.type() == ccnpy.flic.EncryptedNode.class_type():
                assert node is None
                node = ccnpy.flic.EncryptedNode.parse(tlv)
            elif tlv.type() == ccnpy.flic.AuthTag.class_type():
                auth_tag = ccnpy.flic.AuthTag.parse(tlv)
            else:
                raise ValueError("Unsupported TLV %r" % tlv)
            offset += len(tlv)

        return cls(security_ctx=security_ctx, node=node, auth_tag=auth_tag)

    def serialize(self):
        return self._wire_format

    def security_ctx(self):
        return self._security_ctx

    def node(self):
        """

        :return: a ccnpy.flic.Node or ccnpy.flic.EncryptedNode
        """
        return self._node

    def auth_tag(self):
        return self._auth_tag
