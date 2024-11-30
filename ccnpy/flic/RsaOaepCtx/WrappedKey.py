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
from typing import Tuple

from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import OctetTlvType
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class WrappedKey(OctetTlvType):
    @classmethod
    def class_type(cls):
        return TlvNumbers.T_WRAPPED_KEY

    @classmethod
    def create(cls, wrapping_key: RsaKey, key: array | bytes, salt: int):
        if salt is not None and (salt < 0 or salt > 0xFFFFFFFF):
            raise ValueError(f'If salt is specified, it must be unsigned 4-byte integer, got: {salt}')

        plaintext = Tlv.uint32_to_array(salt)
        plaintext.extend(key)
        ciphertext = wrapping_key.encrypt_oaep_sha256(plaintext)
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

    def decrypt(self, wrapping_key: RsaKey) -> Tuple[int, array]:
        plaintext = wrapping_key.decrypt_oaep_sha256(self._value)
        if len(plaintext) < 20:
            raise ValueError("There must be at least 20 bytes (salt + 128 bit key")

        salt = Tlv.array_to_number(plaintext[0:4])
        key = plaintext[4:]

        return salt, key
