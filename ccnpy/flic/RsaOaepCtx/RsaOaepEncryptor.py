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

from .WrappedKey import WrappedKey
from ..aeadctx.AeadImpl import AeadImpl
from ..ManifestEncryptor import ManifestEncryptor
from ..tlvs.KeyNumber import KeyNumber
from ...crypto.AeadKey import AeadGcm, AeadKey
from ...crypto.RsaKey import RsaKey


class RsaOaepEncryptor(ManifestEncryptor):

    @classmethod
    def create_with_new_key(cls, wrapping_key: RsaKey):
        """
        Creates with a random content encryption key and salt.

        :param wrapping_key: The key encryption key
        """
        key = AeadGcm.generate(256)
        salt = os.urandom(4)
        key_number = KeyNumber(os.urandom(4))
        return cls(wrapping_key=wrapping_key, key=key, salt=salt, key_number=key_number)

    def __init__(self, wrapping_key: RsaKey, key: AeadKey, key_number: KeyNumber, salt=None):
        self._psk = AeadImpl(key, key_number, salt)
        self._wrapped_cyphertext = wrapping_key.encrypt_oaep_sha256()
        self._wrapped_key = WrappedKey(key=key, salt=salt)

    def encrypt(self, node):
        return self._psk.encrypt(node)
