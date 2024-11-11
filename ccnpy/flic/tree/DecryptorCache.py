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
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor


class DecryptorCache:
    """
    cache or create an AES decryptor.

    This implementation currently only remembers the last-used decryptor.  This is sufficient for the
    prototype demonstration.
    """

    def __init__(self, keystore: InsecureKeystore):
        self._keystore = keystore
        self._last_key_num = None
        self._last_decryptor = None

    def get_or_create(self, key_num: int):
        if key_num == self._last_key_num:
            return self._last_decryptor
        self._last_key_num = key_num
        self._last_decryptor = self._create(key_num)
        return self._last_decryptor

    def _create(self, key_num) -> AeadDecryptor:
        key = self._keystore.get_aes_key(key_num)
        salt = self._keystore.get_aes_salt(key_num)
        return AeadDecryptor(key, key_num, salt=salt)
