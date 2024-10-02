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

import ccnpy


class AuthTag(ccnpy.Payload):
    """
    AuthTag works just like ccnpy.Payload -- it stores a byte array.
    """
    __T_AUTHTAG = 0x0003

    @classmethod
    def class_type(cls):
        return cls.__T_AUTHTAG

    def __init__(self, value):
        ccnpy.Payload.__init__(self, value)

    def __repr__(self):
        return "AuthTag: %r" % ccnpy.DisplayFormatter.hexlify(self._value)
