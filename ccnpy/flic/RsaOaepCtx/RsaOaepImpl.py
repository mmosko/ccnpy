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

from ccnpy.flic.tlvs.AuthTag import AuthTag
from ccnpy.flic.tlvs.EncryptedNode import EncryptedNode
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.Node import Node
from .RsaOaepWrapper import RsaOaepWrapper
from ..aeadctx.AeadImpl import AeadImpl
from ..tlvs.KeyNumber import KeyNumber
from ..tlvs.RsaOaepCtx import RsaOaepCtx
from ...crypto.AeadKey import AeadKey
from ...crypto.DecryptionError import DecryptionError


class RsaOaepImpl(AeadImpl):
    """
    The RSA-OAEP algorithm.  it uses AeadImpl for the actual encryption.

    Typically, you will use `RsaOaepImpl.create_manifest(...)` to create a Manifest TLV out of
    a Node.
    """

    def __init__(self, wrapper: RsaOaepWrapper, key: AeadKey, key_number: KeyNumber, salt: int):
        if not isinstance(key, AeadKey):
            raise TypeError("key must be AesGcmKey")
        super().__init__(key=key, key_number=key_number, salt=salt)
        self._wrapper = wrapper
        self._aead_impl = AeadImpl(key=key, key_number=key_number)

    def __repr__(self):
        return f'RsaOaepImpl: (num: {self._key_number}, salt: {self._salt}, mode: {self._key.aead_mode()}, key len: {len(self._key)}, wrapper: {self._wrapper})'

    def encrypt(self, node: Node, include_wrapper: bool = False):
        """

        :param node: A Node
        :param include_wrapper: Include the RsaOaepWrapper in the security context
        :return: (security_ctx, encrypted_node, auth_tag)
        """
        if not isinstance(node, Node):
            raise TypeError("node must be Node")

        nonce = self._generate_nonce()
        aead_data = self._create_aead_data(nonce)
        wrapper = self._wrapper if include_wrapper else None
        security_ctx = RsaOaepCtx(aead_data=aead_data, rsa_oaep_wrapper=wrapper)
        return self.encrypt_with_security_ctx(node, security_ctx)

    def create_encrypted_manifest(self, node: Node, include_wrapper: bool = False):
        """

        :param node: A Node to encrypt and wrap in a Manifest
        :param include_wrapper: Include the RsaOaepWrapper in the security context
        :return: A Manifest
        """

        security_ctx, encrypted_node, auth_tag = self.encrypt(node, include_wrapper)
        manifest = Manifest(security_ctx=security_ctx, node=encrypted_node, auth_tag=auth_tag)
        return manifest

    def decrypt_node(self, security_ctx: RsaOaepCtx, encrypted_node: EncryptedNode, auth_tag: AuthTag):
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
        if not isinstance(security_ctx, RsaOaepCtx):
            raise TypeError("security_ctx must be a RsaOaepCtx")
        if auth_tag is None:
            raise ValueError("auth_tag must not be None")

        node = self.decrypt_node(security_ctx=security_ctx,
                                 encrypted_node=encrypted_node,
                                 auth_tag=auth_tag)

        manifest = Manifest(node=node)
        return manifest
