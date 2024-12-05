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
from array import array
from typing import Optional

from .AeadParameters import AeadParameters
from ..tlvs.AeadMode import AeadMode
from ..tlvs.KdfData import KdfData
from ..tlvs.KeyNumber import KeyNumber
from ..tlvs.Nonce import Nonce
from ...core.Serializable import Serializable
from ...core.Tlv import Tlv
from ...core.TlvType import TlvType


class AeadData(Serializable):
    """
    Important: AeadData is not a Tlv.  It is the structured value of a Tlv.  it exists in AeadCtx and RsaOaepWrapper.

        AEADData = KeyNum AEADNonce AEADMode

    """
    DEBUG=False

    def __init__(self, key_number: KeyNumber | int, nonce: Nonce | array, mode: AeadMode, kdf_data: Optional[KdfData] = None):
        """

        :param key_number: An integer
        :param nonce: A byte array
        :param mode: One of the allowed modes (use a class create_x method to create)
        :param kdf_data: Optional use of a KDF for the key
        """
        self._key_number = key_number if isinstance(key_number, KeyNumber) else KeyNumber(key_number)
        self._nonce = nonce if isinstance(nonce, Nonce) else Nonce(nonce)
        self._mode = mode
        self._kdf_data = kdf_data
        self._wire_format = Tlv.flatten([self._key_number, self._nonce, self._mode, self._kdf_data])

    def __eq__(self, other):
        if not isinstance(other, AeadData):
            return False
        return self._wire_format == other._wire_format

    def __repr__(self):
        return "AeadData: {%r, %r, %r, %r}" % (self.key_number(), self.nonce(), self.mode(), self._kdf_data)

    def __len__(self):
        return len(self._wire_format)

    def __iter__(self):
        # Tlv.flatten requires iterable
        for b in self._wire_format:
            yield b

    def nonce(self) -> Nonce:
        return self._nonce

    def key_number(self) -> KeyNumber:
        return self._key_number

    def mode(self) -> AeadMode:
        return self._mode

    def kdf_data(self) -> Optional[KdfData]:
        return self._kdf_data

    def serialize(self):
        return self._wire_format

    @classmethod
    def parse(cls, tlv_value):
        """
        AeadData is not a TlvType.  It parses the Tlv value of of AeadCtx.
        """

        if cls.DEBUG:
            print(f'AeadData parsing Tlv: {tlv_value}')

        values = TlvType.auto_value_parse(tlv_value, [
            ('key_number', KeyNumber),
            ('nonce', Nonce),
            ('mode', AeadMode),
            ('kdf_data', KdfData)],
            skip_unknown=True)
        return cls(**values)
