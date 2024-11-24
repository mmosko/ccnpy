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
from .WrappedKey import WrappedKey
from ..tlvs.TlvNumbers import TlvNumbers
from ...core.DisplayFormatter import DisplayFormatter
from ...core.HashValue import HashValue, HashFunctionType
from ...core.KeyLink import KeyLink
from ...core.Tlv import Tlv


class RsaOaepWrapper:
    """
        RsaOaepWrapper = KeyId KeyLink HashAlg WrappedKey
            ; KeyId as pre RFC8609 for CCNx
            ; KeyLink as pre RFC8609 for CCNx
        HashAlg = T_HASH_ALG LENGTH alg_number
            ; alg_number from IANA "CCNx Hash Function Types"
        WrappedKey = T_WRAPPED_KEY LENGTH 4OCTET 1*OCTET
            ; Encrypted 4-byte salt plus AES key
    """

    @classmethod
    def create_sha256(cls, key_number, nonce):
        return cls(key_number=key_number, nonce=nonce, mode=cls.__AEAD_AES_128_GCM)

    def __init__(self, key_id: HashValue, key_link: KeyLink, hash_alg: HashFunctionType, wrapped_key: WrappedKey):
        """

        :param key_number: An integer
        :param nonce: A byte array
        :param mode: One of the allowed modes (use a class create_x method to create)
        """
        self.key_number = key_number
        self.nonce = nonce
        self.mode = mode

        self.key_tlv = Tlv(TlvNumbers.T_KEYNUM, Tlv.number_to_array(self.key_number))
        self.nonce_tlv = Tlv(TlvNumbers.T_NONCE, self.nonce)
        self.mode_tlv = Tlv.create_uint8(TlvNumbers.T_AEADMode, self.mode)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "kn: %r, iv: %r, mode: %r" % (self.key_number,
                                                       DisplayFormatter.hexlify(self.nonce),
                                                       self.__mode_string())

    def is_aes_gcm_128(self):
        return self.mode == self.__AEAD_AES_128_GCM

    def is_aes_gcm_256(self):
        return self.mode == self.__AEAD_AES_256_GCM

    def is_aes_ccm_128(self):
        return self.mode == self.__AEAD_AES_128_CCM

    def is_aes_ccm_256(self):
        return self.mode == self.__AEAD_AES_256_CCM

    def nonce(self):
        return self.nonce

    def key_number(self):
        return self.key_number
