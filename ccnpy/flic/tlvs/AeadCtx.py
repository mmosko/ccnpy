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

from .SecurityCtx import SecurityCtx, AeadSecurityCtx
from .TlvNumbers import TlvNumbers
from ..aeadctx.AeadData import AeadData
from ...core.Tlv import Tlv
from ...exceptions.CannotParseError import CannotParseError


class AeadCtx(AeadSecurityCtx):
    """
    The security context for a authenticated encryption, authenticated data algorithms.

    This is analogous to a ValidationAlg implementation,
    such as ccnpy.ValidationAlg_RsaSha256.  This class is used by the `AEAD` class and typically
    the user does not need to touch it.

    Typically, you will use `AEADCtx.create_aes_gcm_256(...)` or `AEADCtx.parse(...)`.

    This class uses the raw IV and does not make any assuptions about how it is generated.  See
    NIST 800-38d for recommendations on constructing the IV and appropriate bit lengths.

        AEADCtx = T_AEAD_CTX LENGTH AEADData
    """
    @classmethod
    def class_type(cls):
        return TlvNumbers.T_AEAD_CTX

    def __init__(self, aead_data: AeadData):
        """

        :param key_number: An integer
        :param nonce: A byte array
        :param mode: One of the allowed modes (use a class create_x method to create)
        """
        super().__init__(aead_data)
        self._tlv = Tlv(SecurityCtx.class_type(),
                        Tlv(self.class_type(), self._aead_data))

    def __eq__(self, other):
        if not isinstance(other, AeadCtx):
            return False
        return self._aead_data == other._aead_data

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "PSK: {%r}" % self._aead_data

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != SecurityCtx.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        inner_tlv = Tlv.deserialize(tlv.value())

        if inner_tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        aead_data = AeadData.parse(inner_tlv.value())
        return cls(aead_data=aead_data)

    def serialize(self):
        return self._tlv.serialize()
