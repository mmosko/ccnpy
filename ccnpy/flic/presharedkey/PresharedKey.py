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
from .PresharedKeyCtx import PresharedKeyCtx
from ..AuthTag import AuthTag
from ..EncryptedNode import EncryptedNode
from ..Manifest import Manifest
from ..Node import Node
from ...core.Tlv import Tlv
from ...crypto.AesGcmKey import AesGcmKey


class PresharedKey:
    """
    The PresharedKey algorithm.

    Typically, you will use `PresharedKey.create_manifest(...)` to create a Manifest TLV out of
    a Node.
    """

    def __init__(self, key, key_number):
        """

        :param key: A AesGcmKey
        :param key_number: An integer used to reference the key
        """
        if not isinstance(key, AesGcmKey):
            raise TypeError("key must be AesGcmKey")

        self._key = key
        self._key_number = key_number

    def encrypt(self, node):
        """

        :param node: A Node
        :return: (security_ctx, encrypted_node, auth_tag)
        """
        if not isinstance(node, Node):
            raise TypeError("node must be Node")

        plaintext = node.serialized_value()
        iv = self._key.nonce()

        security_ctx = None
        if len(self._key) == 128:
            security_ctx = PresharedKeyCtx.create_aes_gcm_128(key_number=self._key_number, iv=iv)
        elif len(self._key) == 256:
            security_ctx = PresharedKeyCtx.create_aes_gcm_256(key_number=self._key_number, iv=iv)
        else:
            raise ValueError("Unsupported key length %r" % len(self._key))

        ciphertext, a = self._key.encrypt(nonce=iv,
                                          plaintext=plaintext,
                                          associated_data=security_ctx.serialize())

        encrypted_node = EncryptedNode(ciphertext)
        auth_tag = AuthTag(a)
        return security_ctx, encrypted_node, auth_tag

    def create_encrypted_manifest(self, node):
        """

        :param node: A Node to encrypt and wrap in a Manifest
        :return: A Manifest
        """

        security_ctx, encrypted_node, auth_tag = self.encrypt(node)
        manifest = Manifest(security_ctx=security_ctx, node=encrypted_node, auth_tag=auth_tag)
        return manifest

    def decrypt_node(self, security_ctx, encrypted_node, auth_tag):
        """
        Example:
            manifest = Manifest.deserialize(payload.value())
            if isinstance(manifest.security_ctx(), PresharedKeyCtx):
                # keystore is not necessarily provided
                key = keystore.get(manifest.security_ctx().key_number())
                psk = PresharedKey(key)
                node = psk.decrypt_node(manifest.security_ctx(),
                                        manifest.node(),
                                        manifest.auth_tag())

        :param security_ctx: A PresharedKeyCtx
        :param encrypted_node: A EncryptedNode
        :param auth_tag: A AuthTag
        :return: a Node
        """

        if not isinstance(encrypted_node, EncryptedNode):
            raise TypeError("encrypted_node must be EncryptedNode")
        if security_ctx is None:
            raise ValueError("security context must not be None")
        if not isinstance(security_ctx, PresharedKeyCtx):
            raise TypeError("security_ctx must be a PresharedKeyCtx")
        if auth_tag is None:
            raise ValueError("auth_tag must not be None")
        if not isinstance(auth_tag, AuthTag):
            raise TypeError("auth_tag must be AuthTag")

        if security_ctx.key_number() != self._key_number:
            raise ValueError("security_ctx.key_number %r != our key_number %r" %
                             (security_ctx.key_number(), self._key_number))

        plaintext = self._key.decrypt(nonce=security_ctx.iv(),
                                      ciphertext=encrypted_node.value(),
                                      associated_data=security_ctx.serialize(),
                                      auth_tag=auth_tag.value())

        node_tlv = Node.create_tlv(plaintext)
        node = Node.parse(node_tlv)
        return node

    def decrypt_manifest(self, encrypted_manifest):
        """
        Example:
            manifest = Manifest.deserialize(payload.value())
            if isinstance(manifest.security_ctx(), PresharedKeyCtx):
                # keystore is not necessarily provided
                key = keystore.get(manifest.security_ctx().key_number())
                psk = PresharedKey(key)
                manifest = psk.decrypt_to_manifest(manifest)

        :param encrypted_manifest:
        :return: A decrypted manifest
        """
        if not isinstance(encrypted_manifest, Manifest):
            raise TypeError("encrypted_manifest must be Manifest")

        security_ctx = encrypted_manifest.security_ctx()
        encrypted_node = encrypted_manifest.node()
        auth_tag = encrypted_manifest.auth_tag()

        if not isinstance(encrypted_node, EncryptedNode):
            raise TypeError("manifest did not contain an encrypted node")
        if security_ctx is None:
            raise ValueError("security context must not be None")
        if not isinstance(security_ctx, PresharedKeyCtx):
            raise TypeError("security_ctx must be a PresharedKeyCtx")
        if auth_tag is None:
            raise ValueError("auth_tag must not be None")

        node = self.decrypt_node(security_ctx=security_ctx,
                                 encrypted_node=encrypted_node,
                                 auth_tag=auth_tag)

        manifest = Manifest(node=node)
        return manifest
