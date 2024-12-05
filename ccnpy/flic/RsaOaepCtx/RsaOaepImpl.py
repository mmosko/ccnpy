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
from array import array
from typing import Optional

from ccnpy.flic.tlvs.AuthTag import AuthTag
from ccnpy.flic.tlvs.EncryptedNode import EncryptedNode
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.Node import Node
from .RsaOaepWrapper import RsaOaepWrapper
from ..aeadctx.AeadData import AeadData
from ..aeadctx.AeadImpl import AeadImpl
from ..aeadctx.AeadParameters import AeadParameters
from ..tlvs.RsaOaepCtx import RsaOaepCtx
from ...crypto.AeadKey import AeadKey, AeadGcm, AeadCcm
from ...crypto.DecryptionError import DecryptionError
from ...crypto.InsecureKeystore import InsecureKeystore, KeyNumberNotFoundError, KeyIdNotFoundError


class RsaOaepImpl(AeadImpl):
    """
    The RSA-OAEP algorithm.  it uses AeadImpl for the actual encryption.

    Each instance of RsaOaepImpl for a specific `(key_id, key_number)` pair.

    Typically, you will use `RsaOaepImpl.create_manifest(...)` to create a Manifest TLV out of
    a Node.
    """

    @classmethod
    def create(cls, keystore: InsecureKeystore, rsa_oaep_ctx: RsaOaepCtx):
        """
        Instantiate based on security context.

            1) If we already have KeyNum in our keystore, use it.
            2) If not, try decrypting the wrapped key using an RSA key in the keystore.
            3) If we don't have the RSA key, should fetch it from the KeyLink.  For our current purposes, we throw
               an KeyIdNotFoundError exception.
        """
        # Step 1: we already have the KeyNumber
        try:
            return cls._create_by_key_number(keystore, rsa_oaep_ctx)
        except KeyNumberNotFoundError:
            pass

        # Step 2: Try to decrypt
        try:
            return cls._create_by_wrapped_key(keystore, rsa_oaep_ctx)
        except KeyIdNotFoundError:
            raise

    @classmethod
    def _create_by_key_number(cls, keystore: InsecureKeystore, rsa_oaep_ctx: RsaOaepCtx):
        params = keystore.get_aes_key(rsa_oaep_ctx.key_number())
        return cls(wrapper=rsa_oaep_ctx.rsa_oaep_wrapper(), aead_params=params)

    @staticmethod
    def _create_aead_key(aead_data: AeadData, key: array) -> AeadKey:
        # TODO: This should really be encapsualted somewhere else
        if aead_data.mode().is_aes_gcm_128() or aead_data.mode().is_aes_gcm_256():
            return AeadGcm(key)
        if aead_data.mode().is_aes_ccm_128() or aead_data.mode().is_aes_ccm_256():
            return AeadCcm(key)
        raise ValueError(f"Unsupport key mode: {aead_data.mode()}")

    @classmethod
    def _create_by_wrapped_key(cls, keystore: InsecureKeystore, rsa_oaep_ctx: RsaOaepCtx):
        rsa_oaep_wrapper = rsa_oaep_ctx.rsa_oaep_wrapper()
        if rsa_oaep_wrapper is None:
            raise ValueError(f"Cannot decrypt, missing AEAD key and there is no RsaOaepWrapper: {rsa_oaep_ctx}")
        try:
            wrapping_key = keystore.get_rsa(rsa_oaep_wrapper.key_id())
            cls.logger.debug("Wrapping Key: %s", wrapping_key)
            if not wrapping_key.has_private_key():
                raise ValueError(f'The keystore does not have a private key for keyid {rsa_oaep_wrapper.key_id()}')

            aead_salt, aes_key = rsa_oaep_wrapper.wrapped_key().decrypt(
                wrapping_key=wrapping_key,
                aead_data=rsa_oaep_ctx.aead_data())

            aead_key = cls._create_aead_key(rsa_oaep_ctx.aead_data(), aes_key)
            params = AeadParameters(
                key=aead_key,
                key_number=rsa_oaep_ctx.key_number(),
                aead_salt=aead_salt,
                kdf_data=rsa_oaep_ctx.aead_data().kdf_data(),
                kdf_salt=None
            )
            cls.logger.debug('Create from wrapped key: %s', params)
            keystore.add_aes_key(params)
            return cls(wrapper=rsa_oaep_wrapper, aead_params=params)

        except KeyIdNotFoundError as e:
            print(f"Could not find keyid in kestore: {rsa_oaep_ctx.key_id()}")
            raise e

    def __init__(self, wrapper: Optional[RsaOaepWrapper], aead_params: AeadParameters):
        if not isinstance(aead_params, AeadParameters):
            raise TypeError("aead_params must be AeadParameters")
        self._wrapper = wrapper
        super().__init__(params=aead_params)

    def __repr__(self):
        return f'RsaOaepImpl: ({self._params}, {self._wrapper})'

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
        TODO: Update for OAEP

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

        mode = security_ctx.aead_data().mode()
        if self._params.key.aead_mode() == 'GCM':
            if not (mode.is_aes_gcm_128() or mode.is_aes_gcm_256()):
                raise DecryptionError(f'The AES key is for GCM but the manifest is not encrypted with GCM (security ctx type {security_ctx.class_type()})')
        if self._params.key.aead_mode() == 'CCM':
            if not (mode.is_aes_ccm_128() or mode.is_aes_ccm_256()):
                raise DecryptionError(f'The AES key is for CCM but the manifest is not encrypted with CCM (security ctx type {security_ctx.class_type()})')

        plaintext = self._params.key.decrypt(iv=self._iv_from_nonce(security_ctx.aead_data().nonce().value()),
                                      ciphertext=encrypted_node.value(),
                                      associated_data=security_ctx.serialize(),
                                      auth_tag=auth_tag.value())

        node_tlv = Node.create_tlv(plaintext)
        node = Node.parse(node_tlv)
        return node

    def decrypt_manifest(self, encrypted_manifest):
        """
        TODO: Update for OAEP

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
