#  Copyright 2019 Marc Mosko
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


class Manifest(ccnpy.ContentObject):
    def __init__(self, name=None, expiry_time=None, security_ctx=None, node=None):
        ccnpy.ContentObject.__init__(self, name=name, expiry_time=expiry_time)
        self._type_number = ccnpy.TlvType.T_MANIFEST

        self._security_ctx = security_ctx
        self._node = node

    @classmethod
    def deserialize(cls, tlv):
        # TODO: Finish
        return cls()

    def serialize(self):
        pass

    def security_ctx(self):
        return self._security_ctx

    def node(self):
        return self._node

