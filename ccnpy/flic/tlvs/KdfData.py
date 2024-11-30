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

from .KdfAlg import KdfAlg
from .KdfInfo import KdfInfo
from .TlvNumbers import TlvNumbers
from ...core.Name import Name
from ...core.Tlv import Tlv
from ...core.TlvType import TlvType


class KdfData(TlvType):
    """
    """
    DEBUG = False

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_KDF_DATA

    @classmethod
    def create_hkdf_sha256(cls, kdf_info: Optional[KdfInfo] = None):
        return cls(kdf_alg = KdfAlg.create_hkdf_sha256(), kdf_info=kdf_info)

    @classmethod
    def copy_with_name(cls, kdf_data: 'KdfData', name: Name):
        """Copies the given kdf_data and replaces (or sets) the KdfInfo to the given name."""
        info_bytes = name.serialize()
        return cls(kdf_alg=kdf_data.kdf_alg(), kdf_info=KdfInfo(info_bytes))

    def __init__(self, kdf_alg: KdfAlg, kdf_info: Optional[KdfInfo] = None):
        """
        """
        super().__init__()
        assert isinstance(kdf_alg, KdfAlg)
        assert kdf_info is None or isinstance(kdf_info, KdfInfo)
        self._kdf_alg = kdf_alg
        self._kdf_info = kdf_info

        self._tlv = Tlv(self.class_type(), [self._kdf_alg, self._kdf_info])

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if not isinstance(other, KdfData):
            return False
        return self._tlv == other._tlv

    def __repr__(self):
        return "KdfData: {%r, %r}" % (self._kdf_alg, self._kdf_info)

    def kdf_alg(self) -> KdfAlg:
        return self._kdf_alg

    def kdf_info(self) -> Optional[KdfInfo]:
        return self._kdf_info

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if cls.DEBUG:
            print(f'KdfData parsing Tlv: {tlv}')

        classes = [ ('kdf_alg', KdfAlg),
                   ('kdf_info', KdfInfo)]

        values = cls.auto_parse(tlv, classes)
        return cls(**values)

