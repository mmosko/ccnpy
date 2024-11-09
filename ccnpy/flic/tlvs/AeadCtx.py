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

from ccnpy.flic.tlvs.SecurityCtx import SecurityCtx
from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Tlv import Tlv


class AeadCtx(SecurityCtx):
    """
    The security context for a authenticated encryption, authenticated data algorithms.

    This is analogous to a ValidationAlg implementation,
    such as ccnpy.ValidationAlg_RsaSha256.  This class is used by the `AEAD` class and typically
    the user does not need to touch it.

    Typically, you will use `AEADCtx.create_aes_gcm_256(...)` or `AEADCtx.parse(...)`.

    This class uses the raw IV and does not make any assuptions about how it is generated.  See
    NIST 800-38d for recommendations on constructing the IV and appropriate bit lengths.

    ```
    AEADCtx = TYPE LENGTH AEADData
    AEADData = KeyNum AEADNonce Mode
    KeyNum = TYPE LENGTH INTEGER
    AEADIV = TYPE LENGTH 1*OCTET
    AEADMode = TYPE LENGTH (AEAD_AES_128_GCM / AEAD_AES_256_GCM /
    AEAD_AES_128_CCM / AEAD_AES_128_CCM)
    ```
    """
    __T_AEAD = 0x0001
    __T_KEYNUM = 0x0001
    __T_NONCE = 0x0002
    __T_MODE = 0x0003

    __AEAD_AES_128_GCM = 1
    __AEAD_AES_256_GCM = 2
    __AEAD_AES_128_CCM = 3
    __AEAD_AES_256_CCM = 4
    __allowed_modes = [__AEAD_AES_128_GCM, __AEAD_AES_256_GCM, __AEAD_AES_128_CCM, __AEAD_AES_256_CCM]

    @classmethod
    def class_type(cls):
        return cls.__T_AEAD

    @classmethod
    def create_aes_gcm_128(cls, key_number, nonce):
        return cls(key_number=key_number, nonce=nonce, mode=cls.__AEAD_AES_128_GCM)

    @classmethod
    def create_aes_gcm_256(cls, key_number, nonce):
        return cls(key_number=key_number, nonce=nonce, mode=cls.__AEAD_AES_256_GCM)

    @classmethod
    def create_aes_ccm_128(cls, key_number, nonce):
        return cls(key_number=key_number, nonce=nonce, mode=cls.__AEAD_AES_128_CCM)

    @classmethod
    def create_aes_ccm_256(cls, key_number, nonce):
        return cls(key_number=key_number, nonce=nonce, mode=cls.__AEAD_AES_256_CCM)

    def __mode_string(self):
        if self._mode == self.__AEAD_AES_128_GCM:
            return "AES-GCM-128"
        if self._mode == self.__AEAD_AES_256_GCM:
            return "AES-GCM-256"
        if self._mode == self.__AEAD_AES_128_CCM:
            return "AES-CCM-128"
        if self._mode == self.__AEAD_AES_256_CCM:
            return "AES-CCM-256"
        raise ValueError("Unsupported mode %r" % self._mode)

    def __init__(self, key_number: int, nonce, mode):
        """

        :param key_number: An integer
        :param nonce: A byte array
        :param mode: One of the allowed modes (use a class create_x method to create)
        """
        SecurityCtx.__init__(self)
        self._key_number = key_number
        self._nonce = nonce
        self._mode = mode

        key_tlv = Tlv(self.__T_KEYNUM, Tlv.number_to_array(self._key_number))
        nonce_tlv = Tlv(self.__T_NONCE, self._nonce)
        mode_tlv = Tlv.create_uint8(self.__T_MODE, self._mode)

        self._tlv = Tlv(SecurityCtx.class_type(),
                        Tlv(self.class_type(), [key_tlv, nonce_tlv, mode_tlv]))

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
