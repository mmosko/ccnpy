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
from ccnpy.flic.ManifestDecryptor import ManifestDecryptor
from ccnpy.flic.RsaOaepCtx.RsaOaepDecryptor import RsaOaepDecryptor
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.tlvs.AeadCtx import AeadCtx
from ccnpy.flic.tlvs.RsaOaepCtx import RsaOaepCtx
from ccnpy.flic.tlvs.SecurityCtx import AeadSecurityCtx


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
        self._oaep_decryptor = RsaOaepDecryptor(keystore=self._keystore)

    def get_or_create(self, security_ctx: AeadSecurityCtx):
        # TODO: This is not correct for RsaOaep, as it uses (keyid, keynum) pair as index
        key_num = security_ctx.key_number()
        if key_num == self._last_key_num:
            return self._last_decryptor
        self._last_key_num = key_num
        self._last_decryptor = self._create(security_ctx)
        return self._last_decryptor

    def _create(self, security_ctx: AeadSecurityCtx) -> ManifestDecryptor:
        # TODO: implement for RsaOaep too
        if isinstance(security_ctx, AeadCtx):
            key_num = security_ctx.key_number()
            return AeadDecryptor(self._keystore.get_aes_key(key_num))

        if isinstance(security_ctx, RsaOaepCtx):
            return self._oaep_decryptor
