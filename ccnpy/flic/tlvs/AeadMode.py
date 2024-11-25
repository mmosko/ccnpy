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


from ccnpy.core.TlvType import IntegerTlvType
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers

class AeadMode(IntegerTlvType):
    """
    Identifies the AEAD mode (algorithm) used.

        KeyNum = TYPE LENGTH Integer
    """

    __AEAD_AES_128_GCM = 1
    __AEAD_AES_256_GCM = 2
    __AEAD_AES_128_CCM = 3
    __AEAD_AES_256_CCM = 4
    __allowed_modes = [__AEAD_AES_128_GCM, __AEAD_AES_256_GCM, __AEAD_AES_128_CCM, __AEAD_AES_256_CCM]

    def __mode_string(self):
        if self._value == self.__AEAD_AES_128_GCM:
            return "AES-GCM-128"
        if self._value == self.__AEAD_AES_256_GCM:
            return "AES-GCM-256"
        if self._value == self.__AEAD_AES_128_CCM:
            return "AES-CCM-128"
        if self._value == self.__AEAD_AES_256_CCM:
            return "AES-CCM-256"
        raise ValueError("Unsupported mode %r" % self._value)

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_AEADMode

    @classmethod
    def create_aes_gcm_128(cls):
        return cls(mode=cls.__AEAD_AES_128_GCM)

    @classmethod
    def create_aes_gcm_256(cls):
        return cls(mode=cls.__AEAD_AES_256_GCM)

    @classmethod
    def create_aes_ccm_128(cls):
        return cls(mode=cls.__AEAD_AES_128_CCM)

    @classmethod
    def create_aes_ccm_256(cls):
        return cls(mode=cls.__AEAD_AES_256_CCM)

    def __init__(self, mode):
        super().__init__(mode)

    def __repr__(self):
        return "AeadMode (%r): %r" % (self._value, self.__mode_string())

    def is_aes_gcm_128(self):
        return self._value == self.__AEAD_AES_128_GCM

    def is_aes_gcm_256(self):
        return self._value == self.__AEAD_AES_256_GCM

    def is_aes_ccm_128(self):
        return self._value == self.__AEAD_AES_128_CCM

    def is_aes_ccm_256(self):
        return self._value == self.__AEAD_AES_256_CCM

