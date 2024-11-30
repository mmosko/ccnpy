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
from typing import Optional, Dict

from ccnpy.core.KeyId import KeyId
from ccnpy.crypto.AeadKey import AeadKey
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.tlvs.KeyNumber import KeyNumber


class KeyIdNotFoundError(RuntimeError):
    pass

class KeyNumberNotFoundError(RuntimeError):
    pass


class InsecureKeystore:
    """
    This is a prototype keystore for symmetric and asymmetric keys.  It is not secure.  It should not be used
    in a real environment.  We provide it for the example utilities.
    """
    logger = logging.getLogger(__name__)

    def __init__(self):
        self._asymmetric_by_name = {}
        self._asymmetric_by_keyid = {}
        self._symmetric_by_keynum: Dict[int, AeadParameters] = {}

    def add_rsa_key(self, name, key: RsaKey):
        assert key is not None
        self._asymmetric_by_name[name] = key
        self._asymmetric_by_keyid[key.keyid()] = key
        self.logger.debug("name %s, key %s", name, key.keyid())
        return self

    def add_aes_key(self, params: AeadParameters):
        assert params is not None
        self._symmetric_by_keynum[params.key_number.value()] = params
        self.logger.debug("params %s", params)
        return self

    def get_aes_key(self, key_num: KeyNumber) -> AeadParameters:
        try:
            return self._symmetric_by_keynum[key_num.value()]
        except KeyError as e:
            raise KeyNumberNotFoundError(e)

    def get_rsa(self, name_or_keyid) -> RsaKey:
        if isinstance(name_or_keyid, KeyId):
            name_or_keyid = name_or_keyid.digest()
        if name_or_keyid in self._asymmetric_by_keyid:
            result = self._asymmetric_by_keyid[name_or_keyid]
            self.logger.debug("lookup %s returns %s", name_or_keyid, result)
            return result
        else:
            try:
                result = self._asymmetric_by_name[name_or_keyid]
                self.logger.debug("lookup %s returns %s", name_or_keyid, result)
                return result
            except KeyError as e:
                raise KeyIdNotFoundError(f'Could not find name or keyid: {name_or_keyid}')

    def get_rsa_pub_key(self, keyid) -> RsaKey:
        try:
            k = self._asymmetric_by_keyid[keyid]
            if k.has_public_key():
                return k
            else:
                raise KeyIdNotFoundError(f'Key matching keyid {keyid} has no public key')
        except KeyError as e:
            raise KeyIdNotFoundError(e)
