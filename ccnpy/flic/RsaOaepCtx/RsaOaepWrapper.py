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

from .HashAlg import HashAlg
from .WrappedKey import WrappedKey
from ...core.HashValue import HashFunctionType
from ...core.KeyId import KeyId
from ...core.KeyLink import KeyLink
from ...core.Serializable import Serializable
from ...core.Tlv import Tlv
from ...core.TlvType import TlvType


class RsaOaepWrapper(Serializable):
    """
        NOTE: RsaOaepWrapper is not a TLV, it is a serializable buffer.

        RsaOaepWrapper = KeyId KeyLink HashAlg WrappedKey
            ; KeyId as pre RFC8609 for CCNx
            ; KeyLink as pre RFC8609 for CCNx
        HashAlg = T_HASH_ALG LENGTH alg_number
            ; alg_number from IANA "CCNx Hash Function Types"
        WrappedKey = T_WRAPPED_KEY LENGTH RsaOaepEnc(salt, aes_key)
            ; Encrypted 4-byte salt plus AES key
    """

    DEBUG=False

    @classmethod
    def create_sha256(cls, key_id: KeyId, wrapped_key: WrappedKey, key_link: Optional[KeyLink]=None):
        return cls(key_id=key_id, key_link=key_link, wrapped_key=wrapped_key, hash_alg=HashAlg(HashFunctionType.T_SHA_256))

    def __init__(self, key_id: KeyId, hash_alg: HashAlg, wrapped_key: WrappedKey, key_link: Optional[KeyLink]=None):
        """

        :param key_number: An integer
        :param nonce: A byte array
        :param mode: One of the allowed modes (use a class create_x method to create)
        """
        assert isinstance(key_id, KeyId)

        self._key_id = key_id
        self._key_link = key_link
        self._wrapped_key = wrapped_key
        self._hash_alg = hash_alg
        self._wire_format = Tlv.flatten([self._key_id, self._key_link, self._hash_alg, self._wrapped_key])

    def __eq__(self, other):
        if not isinstance(other, RsaOaepWrapper):
            return False
        return self._wire_format == other._wire_format

    def __len__(self):
        return len(self._wire_format)

    def __repr__(self):
        return "{%r, %r, %r, %r}" % (self._key_id, self._key_link, self._hash_alg, self._wrapped_key)

    def key_id(self) -> KeyId:
        return self._key_id

    def key_link(self) -> KeyLink:
        return self._key_link

    def is_sha_256(self):
        return self._hash_alg.value() == HashFunctionType.T_SHA_256

    def is_sha_512(self):
        return self._hash_alg.value() == HashFunctionType.T_SHA_512

    def wrapped_key(self) -> WrappedKey:
        return self._wrapped_key

    def serialize(self):
        return self._wire_format

    @classmethod
    def parse(cls, tlv_value):
        """
        RsaOaepWrapper is not a TlvType.  It parses the Tlv value of of RsaOaepCtx.
        """
        if cls.DEBUG:
            print(f'RsaOaepWrapper parsing Tlv value: {tlv_value}')

        values = TlvType.auto_value_parse(tlv_value, [
            ('key_id', KeyId),
            ('key_link', KeyLink),
            ('hash_alg', HashAlg),
            ('wrapped_key', WrappedKey)],
            skip_unknown=True)

        # When used inside RsaOaepCtx, it may be the case that none of these parameters exist.
        # If all the dictionary entries are none, do not instantiate the class
        filtered = {k: v for k, v in values.items() if v is not None}
        if len(filtered) == 0:
            if cls.DEBUG:
                print("RsaOaepWrapper found no parameters, returning None")
            return None

        return cls(**values)
