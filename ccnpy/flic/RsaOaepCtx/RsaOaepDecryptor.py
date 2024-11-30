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
import logging
from typing import Dict, Tuple

from .RsaOaepImpl import RsaOaepImpl
from ..ManifestDecryptor import ManifestDecryptor
from ..tlvs.KeyNumber import KeyNumber
from ..tlvs.RsaOaepCtx import RsaOaepCtx
from ...core.KeyId import KeyId
from ...crypto.InsecureKeystore import InsecureKeystore


class RsaOaepDecryptor(ManifestDecryptor):
    logger = logging.getLogger(__name__)

    class ImplCache:
        def __init__(self):
            self.cache: Dict[Tuple[KeyId, KeyNumber], RsaOaepImpl] = {}

        def get(self, key_id: KeyId, key_number: KeyNumber) -> RsaOaepImpl:
            return self.cache[(key_id, key_number)]

        def add(self, key_id: KeyId, key_number: KeyNumber, impl: RsaOaepImpl):
            self.cache[(key_id, key_number)] = impl

    def __init__(self, keystore: InsecureKeystore):
        self._keystore = keystore
        self._cache = RsaOaepDecryptor.ImplCache()

    def _get_impl(self, security_ctx: RsaOaepCtx) -> RsaOaepImpl:
        try:
            return self._cache.get(key_id=security_ctx.key_id(), key_number=security_ctx.key_number())
        except KeyError:
            pass

        impl = RsaOaepImpl.create(keystore=self._keystore, rsa_oaep_ctx=security_ctx)
        self._cache.add(key_id=security_ctx.key_id(), key_number=security_ctx.key_number(), impl=impl)
        self.logger.debug('Create new impl: %s', impl)
        return impl

    def decrypt_manifest(self, manifest):
        impl = self._get_impl(security_ctx=manifest.security_ctx())
        return impl.decrypt_manifest(manifest)

    def decrypt_node(self, security_ctx, encrypted_node, auth_tag):
        impl = self._get_impl(security_ctx=security_ctx())
        return impl.decrypt_node(security_ctx, encrypted_node, auth_tag)
