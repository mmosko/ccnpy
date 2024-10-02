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



import ccnpy
import ccnpy.crypto

import ccnpy.flic

from ccnpy.flic.presharedkey import PresharedKeyCtx

class PresharedKey:
    """
    The PresharedKey algorithm.

    Typically, you will use `PresharedKey.create_manifest(...)` to create a Manifest TLV out of
    a ccnpy.flic.Node.
    """
    def __init__(self, key, key_number):
        """

        :param key: A ccnpy.crypto.AesGcmKey
        :param key_number: An integer used to reference the key
        """
        if not isinstance(key, ccnpy.crypto.AesGcmKey):
            raise TypeError("key must be ccnpy.crypto.AesGcmKey")

        self._key = key
        self._key_number = key_number

    def encrypt(self, node):
        """

        :param node: A ccnpy.flic.Node
        :return: (security_ctx, encrypted_node, auth_tag)
        """
        if not isinstance(node, ccnpy.flic.Node):
            raise TypeError("node must be ccnpy.flic.Node")

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

        encrypted_node = ccnpy.flic.EncryptedNode(ciphertext)
        auth_tag = ccnpy.flic.AuthTag(a)
        return security_ctx, encrypted_node, auth_tag

    def create_encrypted_manifest(self, node):
        """

        :param node: A ccnpy.flic.Node to encrypt and wrap in a Manifest
        :return: A ccnpy.flic.Manifest
        """

        security_ctx, encrypted_node, auth_tag = self.encrypt(node)
        manifest = ccnpy.flic.Manifest(security_ctx=security_ctx, node=encrypted_node, auth_tag=auth_tag)
        return manifest

    def decrypt_node(self, security_ctx, encrypted_node, auth_tag):
        """
        Example:
            manifest = ccnpy.flic.Manifest.deserialize(payload.value())
            if isinstance(manifest.security_ctx(), ccnpy.flic.PresharedKeyCtx):
                # keystore is not necessarily provided
                key = keystore.get(manifest.security_ctx().key_number())
                psk = ccnpy.flic.PresharedKey(key)
                node = psk.decrypt_node(manifest.security_ctx(),
                                        manifest.node(),
                                        manifest.auth_tag())

        :param security_ctx: A ccnpy.flic.PresharedKeyCtx
        :param encrypted_node: A ccnpy.flic.EncryptedNode
        :param auth_tag: A ccnpy.flic.AuthTag
        :return: a ccnpy.flic.Node
        """

        if not isinstance(encrypted_node, ccnpy.flic.EncryptedNode):
            raise TypeError("encrypted_node must be ccnpy.flic.EncryptedNode")
        if security_ctx is None:
            raise ValueError("security context must not be None")
        if not isinstance(security_ctx, ccnpy.flic.presharedkey.PresharedKeyCtx):
            raise TypeError("security_ctx must be a ccnpy.flic.PresharedKeyCtx")
        if auth_tag is None:
            raise ValueError("auth_tag must not be None")
        if not isinstance(auth_tag, ccnpy.flic.AuthTag):
            raise TypeError("auth_tag must be ccnpy.flic.AuthTag")

        if security_ctx.key_number() != self._key_number:
            raise ValueError("security_ctx.key_number %r != our key_number %r" %
                             (security_ctx.key_number(), self._key_number))

        plaintext = self._key.decrypt(nonce=security_ctx.iv(),
                                      ciphertext=encrypted_node.value(),
                                      associated_data=security_ctx.serialize(),
                                      auth_tag=auth_tag.value())

        node_tlv = ccnpy.Tlv(ccnpy.flic.Node.class_type(), plaintext)
        node = ccnpy.flic.Node.parse(node_tlv)
        return node

    def decrypt_manifest(self, encrypted_manifest):
        """
        Example:
            manifest = ccnpy.flic.Manifest.deserialize(payload.value())
            if isinstance(manifest.security_ctx(), ccnpy.flic.PresharedKeyCtx):
                # keystore is not necessarily provided
                key = keystore.get(manifest.security_ctx().key_number())
                psk = ccnpy.flic.PresharedKey(key)
                manifest = psk.decrypt_to_manifest(manifest)

        :param encrypted_manifest:
        :return: A decrypted manifest
        """
        if not isinstance(encrypted_manifest, ccnpy.flic.Manifest):
            raise TypeError("encrypted_manifest must be ccnpy.flic.Manifest")

        security_ctx = encrypted_manifest.security_ctx()
        encrypted_node = encrypted_manifest.node()
        auth_tag = encrypted_manifest.auth_tag()

        if not isinstance(encrypted_node, ccnpy.flic.EncryptedNode):
            raise TypeError("manifest did not contain an encrypted node")
        if security_ctx is None:
            raise ValueError("security context must not be None")
        if not isinstance(security_ctx, PresharedKeyCtx):
            raise TypeError("security_ctx must be a ccnpy.flic.PresharedKeyCtx")
        if auth_tag is None:
            raise ValueError("auth_tag must not be None")

        node = self.decrypt_node(security_ctx=security_ctx,
                                 encrypted_node=encrypted_node,
                                 auth_tag=auth_tag)

        manifest = ccnpy.flic.Manifest(node=node)
        return manifest

