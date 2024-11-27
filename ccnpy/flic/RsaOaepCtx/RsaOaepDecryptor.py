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

from .AeadImpl import AeadImpl
from .RsaOaepImpl import RsaOaepImpl
from ..ManifestDecryptor import ManifestDecryptor
from ..tlvs.RsaOaepCtx import RsaOaepCtx
from ...crypto.InsecureKeystore import InsecureKeystore


class RsaOaepDecryptor(ManifestDecryptor):
    @classmethod
    def create(cls, keystore: InsecureKeystore, rsa_oaep_ctx: RsaOaepCtx):
        impl = RsaOaepImpl.create(keystore=keystore, rsa_oaep_ctx=rsa_oaep_ctx)

        # def __init__(self, wrapper: Optional[RsaOaepWrapper], key: AeadKey, key_number: KeyNumber, salt: int):

    def __init__(self, keystore: InsecureKeystore)
        self._keystore = keystore
        # if isinstance(salt, bytes):
        #     salt = int.from_bytes(salt)
        # self._wrapped_key = WrappedKey.create(wrapping_key=wrapping_key, key=key.key(), salt=salt)
        # self._wrapper = RsaOaepWrapper.create_sha256(key_id=wrapping_key.keyid(), wrapped_key=self._wrapped_key)
        # self._impl = RsaOaepImpl(wrapper=self._wrapper, key=key, key_number=key_number, salt=salt)

    # def __init__(self, key, key_number: int, salt: Optional[int] = None):
    #     self._psk = AeadImpl(key, key_number, salt)

    def decrypt_manifest(self, manifest):
        return self._psk.decrypt_manifest(manifest)

    def decrypt_node(self, security_ctx, encrypted_node, auth_tag):
        return self._psk.decrypt_node(security_ctx, encrypted_node, auth_tag)
