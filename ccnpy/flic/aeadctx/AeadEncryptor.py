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
from .AeadParameters import AeadParameters
from ..ManifestEncryptor import ManifestEncryptor
from ..tlvs.KdfData import KdfData
from ..tlvs.KeyNumber import KeyNumber
from ...crypto.AeadKey import AeadKey


class AeadEncryptor(ManifestEncryptor):
    def __init__(self, params: AeadParameters):
        self._psk = AeadImpl(params)

    def encrypt(self, node, **kwargs):
        return self._psk.encrypt(node)
