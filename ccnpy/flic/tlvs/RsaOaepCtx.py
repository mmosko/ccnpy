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

from ccnpy.flic.RsaOaepCtx.RsaOaepWrapper import RsaOaepWrapper
from ccnpy.flic.aeadctx.AeadData import AeadData
from ccnpy.flic.tlvs.SecurityCtx import SecurityCtx
from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class RsaOaepCtx(SecurityCtx):
    """
    The security context for RSA-OAEP wrapped keys

    ```
        RsaOaepCtx = T_RSAOAEP_CTX LENGTH RsaOaepData
        RsaOaepData = AEADData [RsaOaepWrapper]
        RsaOaepWrapper = KeyId KeyLink HashAlg WrappedKey
            ; KeyId as pre RFC8609 for CCNx
            ; KeyLink as pre RFC8609 for CCNx
        HashAlg = T_HASH_ALG LENGTH alg_number
            ; alg_number from IANA "CCNx Hash Function Types"
        WrappedKey = T_WRAPPED_KEY LENGTH 4OCTET 1*OCTET
            ; Encrypted 4-byte salt plus AES key
    ```
    """
    @classmethod
    def class_type(cls):
        return TlvNumbers.T_RSAOAEP_CTX

    def __init__(self, aead_data: AeadData, rsa_oaep_wrapper: Optional[RsaOaepWrapper]):
        """

        :param key_number: An integer
        :param nonce: A byte array
        :param mode: One of the allowed modes (use a class create_x method to create)
        """
        SecurityCtx.__init__(self)
        self._tlv = None

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "PSK: {kn: %r, iv: %r, mode: %r}" % (self._key_number,
                                                       DisplayFormatter.hexlify(self._nonce),
                                                       self.__mode_string())

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise ValueError("Incorrect TLV type %r" % tlv.type())

        key_number = nonce = mode = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            if inner_tlv.type() == cls.__T_KEYNUM:
                assert key_number is None
                key_number = inner_tlv.value_as_number()
            elif inner_tlv.type() == cls.__T_NONCE:
                assert nonce is None
                nonce = inner_tlv.value()
            elif inner_tlv.type() == cls.__T_MODE:
                assert mode is None
                mode = inner_tlv.value_as_number()
                if mode not in cls.__allowed_modes:
                    raise ValueError("Unsupported mode %r" % inner_tlv)
            else:
                raise ValueError("Unsupported TLV %r" % inner_tlv)
            offset += len(inner_tlv)

        return cls(key_number=key_number, nonce=nonce, mode=mode)

    def serialize(self):
        return self._tlv.serialize()

    def is_aes_gcm_128(self):
        return self._mode == self.__AEAD_AES_128_GCM

    def is_aes_gcm_256(self):
        return self._mode == self.__AEAD_AES_256_GCM

    def is_aes_ccm_128(self):
        return self._mode == self.__AEAD_AES_128_CCM

    def is_aes_ccm_256(self):
        return self._mode == self.__AEAD_AES_256_CCM

    def nonce(self):
        return self._nonce

    def key_number(self):
        return self._key_number
