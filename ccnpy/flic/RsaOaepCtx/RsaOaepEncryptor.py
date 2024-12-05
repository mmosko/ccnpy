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
import os
import uuid
from typing import Optional

from .RsaOaepImpl import RsaOaepImpl
from .RsaOaepWrapper import RsaOaepWrapper
from .WrappedKey import WrappedKey
from ..ManifestEncryptor import ManifestEncryptor
from ..aeadctx.AeadParameters import AeadParameters
from ..tlvs.KdfAlg import KdfAlg
from ..tlvs.KdfData import KdfData
from ..tlvs.KdfInfo import KdfInfo
from ..tlvs.KeyNumber import KeyNumber
from ...core.KeyId import KeyId
from ...crypto.AeadKey import AeadGcm, AeadKey
from ...crypto.RsaKey import RsaKey


class RsaOaepEncryptor(ManifestEncryptor):
    """
    TODO: Convert to being Keystore based
    """

    @classmethod
    def create_with_new_content_key(cls, wrapping_key: RsaKey, kdf_data: Optional[KdfData]):
        """
        Creates with a random content encryption key and salt.

        :param wrapping_key: The key encryption key
        """
        key = AeadGcm.generate(256)
        salt = int.from_bytes(os.urandom(4))
        key_number = KeyNumber(os.urandom(4))

        return cls(
            wrapping_key=wrapping_key,
            params=AeadParameters(
                key=key,
                aead_salt=salt,
                key_number=key_number,
                kdf_data=kdf_data))

    def __init__(self, wrapping_key: RsaKey, params: AeadParameters):
        self._wrapped_key = WrappedKey.create(wrapping_key=wrapping_key, params=params)
        self._wrapper = RsaOaepWrapper.create_sha256(key_id=KeyId(wrapping_key.keyid()), wrapped_key=self._wrapped_key)
        self._impl = RsaOaepImpl(wrapper=self._wrapper, aead_params=params)

    def encrypt(self, node, **kwargs):
        return self._impl.encrypt(node, **kwargs)
