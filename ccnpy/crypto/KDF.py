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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ccnpy.crypto.HpkeKdfIdentifiers import HpkeKdfIdentifiers


class KDF:
    @classmethod
    def derive(cls,
               kdf_id: HpkeKdfIdentifiers,
               input_key: bytes,
               length: int,
               info: Optional[bytes] = None,
               salt: Optional[bytes] = None):
        """
        :param kdf_id: The RFC 9180 KDF identifier
        :param input_key: The key derivation key (cryptographic key)
        :param length: The number of bytes of output
        :param info: The optional FixedInfo
        :param salt: An optional salt for the KDF (if used, should be consistent for the key).
        """
        if kdf_id == HpkeKdfIdentifiers.HKDF_SHA256:
            hash_alg = hashes.SHA256()
        elif kdf_id == HpkeKdfIdentifiers.HKDF_SHA384:
            hash_alg = hashes.SHA384()
        elif kdf_id == HpkeKdfIdentifiers.HKDF_SHA512:
            hash_alg = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported kdf_id: {kdf_id}")

        return cls._derive(hash_alg=hash_alg,
                           input_key=input_key,
                           length=length,
                           salt=salt,
                           info=info)

    @classmethod
    def _derive(cls, hash_alg: HashAlgorithm, input_key: bytes, length: int, salt: bytes, info: bytes):
        hkdf = HKDF(
            algorithm=hash_alg,
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(input_key)

