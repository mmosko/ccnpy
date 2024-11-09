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

from ccnpy.flic.tlvs.AeadCtx import AeadCtx
from ccnpy.flic.tlvs.AuthTag import AuthTag
from ccnpy.flic.tlvs.EncryptedNode import EncryptedNode
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.Node import Node
from ...crypto.AeadKey import AeadKey, AeadGcm, AeadCcm
from ...crypto.DecryptionError import DecryptionError


class AeadImpl:
    """
    The AEAD algorithm.

    Typically, you will use `AeadImpl.create_manifest(...)` to create a Manifest TLV out of
    a Node.
    """

    def __init__(self, key: AeadKey, key_number: int, salt: Optional[int]=None):
        """

        :param key: A AesGcmKey
        :param key_number: An integer used to reference the key
        """
        if not isinstance(key, AeadKey):
            raise TypeError("key must be AesGcmKey")

        self._key = key
        self._key_number = key_number
        self._salt = salt.to_bytes(4, byteorder='big') if salt is not None else None
        print(self)

    def __repr__(self):
        return f'AeadImpl: (num: {self._key_number}, salt: {self._salt}, mode: {self._key.aead_mode()}, key len: {len(self._key)})'

    def _generate_nonce(self):
        if self._salt is None:
            return self._key.nonce(96)

        salt_len = len(self._salt) * 8
        return self._key.nonce(96 - salt_len)

    def _iv_from_nonce(self, nonce):
        if self._salt is None:
            return nonce
        return self._salt + nonce

    def _create_gcm_ctx(self, nonce):
        if len(self._key) == 128:
            return AeadCtx.create_aes_gcm_128(key_number=self._key_number, nonce=nonce)
        elif len(self._key) == 256:
            return AeadCtx.create_aes_gcm_256(key_number=self._key_number, nonce=nonce)
        else:
            raise ValueError("Unsupported key length %r" % len(self._key))

    def _create_ccm_ctx(self, nonce):
        if len(self._key) == 128:
            return AeadCtx.create_aes_ccm_128(key_number=self._key_number, nonce=nonce)
        elif len(self._key) == 256:
            return AeadCtx.create_aes_ccm_256(key_number=self._key_number, nonce=nonce)
        else:
            raise ValueError("Unsupported key length %r" % len(self._key))

    def encrypt(self, node):
        """

        :param node: A Node
        :return: (security_ctx, encrypted_node, auth_tag)
        """
        if not isinstance(node, Node):
            raise TypeError("node must be Node")

        plaintext = node.serialized_value()
        nonce = self._generate_nonce()
        iv = self._iv_from_nonce(nonce)

        if isinstance(self._key, AeadGcm):
            security_ctx = self._create_gcm_ctx(nonce)
        elif isinstance(self._key, AeadCcm):
            security_ctx = self._create_ccm_ctx(nonce)
        else:
            raise ValueError(f"Unsupported key type, must be GCM or CCM: {type(self._key)}")

        ciphertext, a = self._key.encrypt(iv=iv,
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

    def decrypt_node(self, security_ctx: AeadCtx, encrypted_node: EncryptedNode, auth_tag: AuthTag):
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

        :param security_ctx: A AeadCtx
        :param encrypted_node: A EncryptedNode
        :param auth_tag: A AuthTag
        :return: a Node
        """

        if security_ctx is None:
            raise ValueError("security context must not be None")
        if auth_tag is None:
            raise ValueError("auth_tag must not be None")
        if security_ctx.key_number() != self._key_number:
            raise ValueError("security_ctx.key_number %r != our key_number %r" %
                             (security_ctx.key_number(), self._key_number))

        if self._key.aead_mode() == 'GCM':
            if not (security_ctx.is_aes_gcm_128() or security_ctx.is_aes_gcm_256()):
                raise DecryptionError(f'The AES key is for GCM but the manifest is not encrypted with GCM (security ctx type {security_ctx.class_type()})')
        if self._key.aead_mode() == 'CCM':
            if not (security_ctx.is_aes_ccm_128() or security_ctx.is_aes_ccm_256()):
                raise DecryptionError(f'The AES key is for CCM but the manifest is not encrypted with CCM (security ctx type {security_ctx.class_type()})')

        plaintext = self._key.decrypt(iv=self._iv_from_nonce(security_ctx.nonce()),
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
        if not isinstance(security_ctx, AeadCtx):
            raise TypeError("security_ctx must be a AeadCtx")
        if auth_tag is None:
            raise ValueError("auth_tag must not be None")

        node = self.decrypt_node(security_ctx=security_ctx,
                                 encrypted_node=encrypted_node,
                                 auth_tag=auth_tag)

        manifest = Manifest(node=node)
        return manifest
