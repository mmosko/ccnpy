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


class ValidationAlg(ccnpy.TlvType):
    def __init__(self, algorithm_id):
        """
        """
        ccnpy.TlvType.__init__(self, algorithm_id)
        pass

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass


class RsaSha256(ValidationAlg):
    def __init(self):
        ValidationAlg.__init__(self, ccnpy.TlvType.T_RSA_SHA256)

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass
