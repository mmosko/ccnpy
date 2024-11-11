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
from ccnpy.crypto.AeadKey import AeadKey
from ccnpy.crypto.RsaKey import RsaKey


class InsecureKeystore:
    """
    This is a prototype keystore for symmetric and asymmetric keys.  It is not secure.  It should not be used
    in a real environment.  We provide it for the example utilities.
    """

    def __init__(self):
        self._asymmetric_by_name = {}
        self._asymmetric_by_keyid = {}
        self._symmetric_by_keynum = {}
        self._salt_by_keynum = {}

    def add_rsa_key(self, name, key: RsaKey):
        self._asymmetric_by_name[name] = key
        self._asymmetric_by_keyid[key.keyid()] = key
        return self

    def add_aes_key(self, key_num, key: AeadKey, salt):
        self._symmetric_by_keynum[key_num] = key
        self._salt_by_keynum[key_num] = salt
        return self

    def get_aes_key(self, key_num) -> AeadKey:
        return self._symmetric_by_keynum[key_num]

    def get_aes_salt(self, key_num):
        return self._salt_by_keynum[key_num]

    def get_rsa(self, name_or_keyid) -> RsaKey:
        if name_or_keyid in self._asymmetric_by_keyid:
            return self._asymmetric_by_keyid[name_or_keyid]
        return self._asymmetric_by_name[name_or_keyid]

    def get_rsa_pub_key(self, keyid) -> RsaKey:
        k = self._asymmetric_by_keyid[keyid]
        if k.has_public_key():
            return k
        else:
            raise ValueError(f'Key matching keyid {keyid} has no public key')
