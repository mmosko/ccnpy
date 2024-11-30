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
import math
from array import array

from .AeadData import AeadData
from .AeadParameters import AeadParameters
from ..tlvs.AeadCtx import AeadCtx
from ..tlvs.AeadMode import AeadMode
from ..tlvs.AuthTag import AuthTag
from ..tlvs.EncryptedNode import EncryptedNode
from ..tlvs.Manifest import Manifest
from ..tlvs.Node import Node
from ..tlvs.SecurityCtx import AeadSecurityCtx
from ...crypto.AeadKey import AeadKey, AeadGcm, AeadCcm
from ...crypto.DecryptionError import DecryptionError
from ...crypto.KDF import KDF


class AeadImpl:
    """
    The AEAD algorithm.

    Typically, you will use `AeadImpl.create_manifest(...)` to create a Manifest TLV out of
    a Node.
    """
    logger = logging.getLogger(__name__)

    def __init__(self, params: AeadParameters):
        """
        If using a KDF and `KdfInfo` is not present, you must set the `KdfInfo` with the CCNx name before
        creating the `AeadImpl`.
        """
        self._params = params
        self.logger.debug(self)

    def  _derive_key(self, key: AeadKey) -> AeadKey:
        if self._params.kdf_data is None:
            return key
        assert self._params.kdf_data.kdf_info() is not None

        mode = AeadMode.from_key(key)
        fixed_info = (b'FLIC'
                      + self._params.key_number.serialize().tobytes()
                      + mode.serialize().tobytes()
                      + self._params.kdf_data.kdf_info().serialize().tobytes())
        derived_bytes = KDF.derive(kdf_id=self._params.kdf_data.kdf_alg().value(),
                                     input_key=key.key(),
                                     length=math.ceil(len(key) / 8),
                                     info=fixed_info,
                                     salt=self._params.kdf_salt
                                     )
        if isinstance(key, AeadGcm):
            return AeadGcm(derived_bytes)
        if isinstance(key, AeadCcm):
            return AeadCcm(derived_bytes)
        raise TypeError(f"Key is unsupported byte: {key}")

    def __repr__(self):
        return f'AeadImpl: {self._params}'

    def _generate_nonce(self):
        if self._params.aead_salt_bytes is None:
            return self._params.key.nonce(96)

        salt_len = len(self._params.aead_salt_bytes) * 8
        return self._params.key.nonce(96 - salt_len)

    def _iv_from_nonce(self, nonce: array):
        if self._params.aead_salt_bytes is None:
            return nonce
        return self._params.aead_salt_bytes + nonce

    def _get_gcm_mode(self, nonce):
        if len(self._params.key) == 128:
            return AeadMode.create_aes_gcm_128()
        elif len(self._params.key) == 256:
            return AeadMode.create_aes_gcm_256()
        else:
            raise ValueError("Unsupported key length %r" % len(self._params.key))

    def _get_ccm_mode(self, nonce):
        if len(self._params.key) == 128:
            return AeadMode.create_aes_ccm_128()
        elif len(self._params.key) == 256:
            return AeadMode.create_aes_ccm_256()
        else:
            raise ValueError("Unsupported key length %r" % len(self._params.key))

    def _create_aead_data(self, nonce):
        if isinstance(self._params.key, AeadGcm):
            mode = self._get_gcm_mode(nonce)
        elif isinstance(self._params.key, AeadCcm):
            mode = self._get_ccm_mode(nonce)
        else:
            raise ValueError(f"Unsupported key type, must be GCM or CCM: {type(self._params.key)}")
        return AeadData(
            key_number=self._params.key_number,
            nonce=nonce,
            mode=mode,
            kdf_data=self._params.kdf_data)

    def _create_aead_ctx(self, nonce) -> AeadCtx:
        return AeadCtx(self._create_aead_data(nonce))

    def encrypt(self, node):
        """

        :param node: A Node
        :return: (security_ctx, encrypted_node, auth_tag)
        """
        if not isinstance(node, Node):
            raise TypeError("node must be Node")

        nonce = self._generate_nonce()
        security_ctx = self._create_aead_ctx(nonce)
        return self.encrypt_with_security_ctx(node, security_ctx)

    def encrypt_with_security_ctx(self, node: Node, security_ctx: AeadSecurityCtx):
        """

        :param node: A Node
        :param security_ctx: The Security context to add to the manifest
        :return: (security_ctx, encrypted_node, auth_tag)
        """
        if not isinstance(node, Node):
            raise TypeError("node must be Node")

        iv = self._iv_from_nonce(security_ctx.nonce().value())

        plaintext = node.serialized_value()
        ciphertext, a = self._params.key.encrypt(iv=iv,
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
        if security_ctx.key_number() != self._params.key_number:
            raise ValueError("security_ctx.key_number %r != our key_number %r" %
                             (security_ctx.key_number(), self._params.key_number))

        if self._params.key.aead_mode() == 'GCM':
            if not (security_ctx.aead_data().mode().is_aes_gcm_128() or security_ctx.aead_data().mode().is_aes_gcm_256()):
                raise DecryptionError(f'The AES key is for GCM but the manifest is not encrypted with GCM (security ctx type {security_ctx.class_type()})')
        if self._params.key.aead_mode() == 'CCM':
            if not (security_ctx.aead_data().mode().is_aes_ccm_128() or security_ctx.aead_data().mode().is_aes_ccm_256()):
                raise DecryptionError(f'The AES key is for CCM but the manifest is not encrypted with CCM (security ctx type {security_ctx.class_type()})')

        plaintext = self._params.key.decrypt(iv=self._iv_from_nonce(security_ctx.nonce().value()),
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
