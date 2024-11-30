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
from ccnpy.crypto.HpkeKdfIdentifiers import HpkeKdfIdentifiers
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class KdfAlg(IntegerTlvType):
    @classmethod
    def class_type(cls):
        return TlvNumbers.T_KDF_ALG

    @classmethod
    def create_hkdf_sha256(cls):
        return cls(HpkeKdfIdentifiers.HKDF_SHA256)

    @classmethod
    def create_hkdf_sha384(cls):
        return cls(HpkeKdfIdentifiers.HKDF_SHA384)

    @classmethod
    def create_hkdf_sha512(cls):
        return cls(HpkeKdfIdentifiers.HKDF_SHA512)

    def __init__(self, value: int | HpkeKdfIdentifiers):
        if isinstance(value, HpkeKdfIdentifiers):
            value = value.number
        super().__init__(value)

    def __repr__(self):
        return f"KdfAlg ({self._value})"

