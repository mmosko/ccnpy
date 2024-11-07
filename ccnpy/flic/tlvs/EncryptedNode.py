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

from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Payload import Payload


class EncryptedNode(Payload):
    """
    EncryptedNode works just like ccnpy.Payload -- it stores a byte array.

    An EncryptedNode represents an encrypted manifest: `SecurityCtx EncryptedNode AuthTag`.
    """
    __T_ENC_NODE = 0x0004

    @classmethod
    def class_type(cls):
        return cls.__T_ENC_NODE

    def __init__(self, value):
        Payload.__init__(self, value)

    def __repr__(self):
        return "EncNode: %r" % DisplayFormatter.hexlify(self._value)
