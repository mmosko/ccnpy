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

from abc import abstractmethod, ABC
from array import array

from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.exceptions.ParseError import ParseError
from ccnpy.flic.aeadctx.AeadData import AeadData
from ccnpy.flic.tlvs.KeyNumber import KeyNumber
from ccnpy.flic.tlvs.Nonce import Nonce
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class SecurityCtx(TlvType, ABC):
    """
    Analogous to the ccnpy.ValidationAlg container.  It is an abstract intermediate class between
    TlvType and the concrete algorithms.

        SecurityCtx = TYPE LENGTH AlgorithmCtx
        AlgorithmCtx = AEADCtx / RsaOaepCtx```
    """

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_SECURITY_CTX

    def __init__(self):
        TlvType.__init__(self)

    @abstractmethod
    def __len__(self):
        pass

    @classmethod
    def parse(cls, tlv):
        # Due to circular reference between SecurityCtx and it's children, need
        # to defer the loading of the children
        from .AeadCtx import AeadCtx
        from .RsaOaepCtx import RsaOaepCtx

        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        inner_tlv = Tlv.deserialize(tlv.value())
        # NOTE: AeadCtx and RsaOaepCtx are responsible for putting the "SecurityCtx" TLV around
        # their own TLV, so they are also responsible for stripping it off.
        if inner_tlv.type() == AeadCtx.class_type():
            return AeadCtx.parse(tlv)
        if inner_tlv.type() == RsaOaepCtx.class_type():
            return RsaOaepCtx.parse(tlv)

        raise ParseError("Unsupported security context %r" % inner_tlv)

    @abstractmethod
    def serialize(self):
        pass

class AeadSecurityCtx(SecurityCtx, ABC):
    def __init__(self, aead_data: AeadData):
        """
        """
        SecurityCtx.__init__(self)
        self._aead_data = aead_data

    def nonce(self) -> Nonce:
        return self._aead_data.nonce()

    def key_number(self) -> KeyNumber:
        return self._aead_data.key_number()

    def aead_data(self):
        return self._aead_data
