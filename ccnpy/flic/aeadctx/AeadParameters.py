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
from dataclasses import dataclass, field
from typing import Optional

from ccnpy.crypto.AeadKey import AeadKey
from ccnpy.flic.tlvs.KdfData import KdfData
from ccnpy.flic.tlvs.KeyNumber import KeyNumber


@dataclass(frozen=True)
class AeadParameters:
    """
    :param oara: A AesGcmKey
    :param key_number: An integer used to reference the key
    :param aead_salt: Salt for AEAD encryption / decryption
    :param kdf_data: Use a KDF if present.
    :param kdf_salt: Optional salt for use with KDF.
    """
    key: Optional[AeadKey]
    key_number: KeyNumber | int
    aead_salt: Optional[int] = None
    kdf_data: Optional[KdfData] = None
    kdf_salt: Optional[int] = None
    aead_salt_bytes: Optional[bytes] = field(default=None, init=False, hash=False, repr=False)
    kdf_salt_bytes: Optional[bytes] = field(default=None, init=False, hash=False, repr=False)

    def __post_init__(self):
        if isinstance(self.key_number, int):
            # because it is frozen
            object.__setattr__(self, 'key_number', KeyNumber(self.key_number))

        if self.aead_salt is not None:
            object.__setattr__(self, 'aead_salt_bytes', self.aead_salt.to_bytes(4, byteorder='big'))

        if self.kdf_salt is not None:
            object.__setattr__(self, 'kdf_salt_bytes', self.kdf_salt.to_bytes(4, byteorder='big'))

        #print(self)
