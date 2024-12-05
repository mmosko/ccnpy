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
from typing import Tuple, Optional

from ccnpy.core.HashValue import HashFunctionType
from ccnpy.core.KeyId import KeyId
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import OctetTlvType
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.flic.RsaOaepCtx.HashAlg import HashAlg
from ccnpy.flic.aeadctx.AeadData import AeadData
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.tlvs.AeadMode import AeadMode
from ccnpy.flic.tlvs.KdfData import KdfData
from ccnpy.flic.tlvs.KeyNumber import KeyNumber
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class WrappedKey(OctetTlvType):
    @classmethod
    def class_type(cls):
        return TlvNumbers.T_WRAPPED_KEY

    @staticmethod
    def _create_label(key_number: KeyNumber, mode: AeadMode,
                      kdf_data: Optional[KdfData], key_id: KeyId, hash_alg: HashAlg):

        if kdf_data is not None:
            kdf_bytes = kdf_data.kdf_info().serialize().tobytes()
        else:
            kdf_bytes = b''

        additional_info = (b'FLIC RSA-OAEP'
                            + key_number.serialize().tobytes()
                            + mode.serialize().tobytes()
                            + kdf_bytes
                            + key_id.serialize().tobytes()
                            + hash_alg.serialize().tobytes())
        return additional_info

    @classmethod
    def create(cls, wrapping_key: RsaKey, params: AeadParameters):
        """
        The label field:

            AdditionalInfo = "FLIC RSA-OAEP" ||
                     KeyNum || AeadMode || [KDFData] ||
                     KeyID || HashAlg ||
                     KeyLink (if present in RsaOaepWrapper)
        """

        if params.aead_salt is not None and (params.aead_salt < 0 or params.aead_salt > 0xFFFFFFFF):
            raise ValueError(f'If salt is specified, it must be unsigned 4-byte integer, got: {params.aead_salt}')

        plaintext = Tlv.uint32_to_array(params.aead_salt)
        plaintext.extend(params.key.key())
        ciphertext = wrapping_key.encrypt_oaep_sha256(
            plaintext=plaintext,
            label=cls._create_label(
                key_id = KeyId(wrapping_key.keyid()),
                key_number = params.key_number,
                mode = AeadMode.from_key(params.key),
                kdf_data = params.kdf_data,
                hash_alg = HashAlg(HashFunctionType.T_SHA_256)
            ))
        return cls(ciphertext=ciphertext)

    def __init__(self, ciphertext):
        """
        :param ciphertext: The RSA-OAEP encrypted (salt, key) pair
        """
        super().__init__(value=ciphertext)

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "WrappedKey: %r" % super().__repr__()

    def serialize(self):
        return self._tlv.serialize()

    def decrypt(self, wrapping_key: RsaKey, aead_data: AeadData) -> Tuple[int, array]:

        plaintext = wrapping_key.decrypt_oaep_sha256(
            cyphertext=self._value,
            label=self._create_label(
                key_id=KeyId(wrapping_key.keyid()),
                key_number=aead_data.key_number(),
                mode=aead_data.mode(),
                kdf_data=aead_data.kdf_data(),
                hash_alg=HashAlg(HashFunctionType.T_SHA_256)
            ))

        if len(plaintext) < 20:
            raise ValueError("There must be at least 20 bytes (salt + 128 bit key")

        salt = Tlv.array_to_number(plaintext[0:4])
        key = plaintext[4:]

        return salt, key
