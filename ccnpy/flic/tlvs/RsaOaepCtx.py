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

from ccnpy.core.Tlv import Tlv
from ccnpy.exceptions.CannotParseError import CannotParseError
from .SecurityCtx import SecurityCtx, AeadSecurityCtx
from .TlvNumbers import TlvNumbers
from ..RsaOaepCtx.RsaOaepWrapper import RsaOaepWrapper
from ..aeadctx.AeadData import AeadData


class RsaOaepCtx(AeadSecurityCtx):
    """
    The security context for RSA-OAEP wrapped keys.  RsaOaepCtx always provides an AeadSecurityCtx, as it uses
    the same AEAD encryption.

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
    DEBUG = False

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_RSAOAEP_CTX

    def __init__(self, aead_data: AeadData, rsa_oaep_wrapper: Optional[RsaOaepWrapper]=None):
        """

        :param aead_data: The mandatory symmetric key data
        :param rsa_oaep_wrapper: The optional (and large) public keu data
        """
        super().__init__(aead_data)
        self._rsa_oaep_wrapper = rsa_oaep_wrapper
        self._tlv = Tlv(SecurityCtx.class_type(),
                        Tlv(self.class_type(), [self._aead_data, self._rsa_oaep_wrapper]))

    def __eq__(self, other):
        if not isinstance(other, RsaOaepCtx):
            return False
        return self._tlv == other._tlv

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "RsaOaepCtx: {aead: %r, wrapper: %r}" % (self._aead_data, self._rsa_oaep_wrapper)

    @classmethod
    def parse(cls, tlv):
        if cls.DEBUG:
            print(f'RsaOaepCtx parsing Tlv: {tlv}')

        if tlv.type() != SecurityCtx.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        inner_tlv = Tlv.deserialize(tlv.value())

        if inner_tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        aead_data = AeadData.parse(inner_tlv.value())
        rsa_oaep_wrapper = RsaOaepWrapper.parse(inner_tlv.value())
        return cls(aead_data=aead_data, rsa_oaep_wrapper=rsa_oaep_wrapper)

    def serialize(self):
        return self._tlv.serialize()

    def key_id(self):
        if self._rsa_oaep_wrapper is not None:
            return self._rsa_oaep_wrapper.key_id()
        return None

    def rsa_oaep_wrapper(self) -> Optional[RsaOaepWrapper]:
        return self._rsa_oaep_wrapper
