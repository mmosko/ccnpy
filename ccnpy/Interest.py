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


class Interest(ccnpy.TlvType):
    def __init__(self, name=None, key_id_restr=None, con_obj_hash_restr=None):
        """

        :param name:
        :param key_id_restr: KeyId Restriction
        :param con_obj_hash_restr: Content Object Hash Restriction
        :param lifetime: Interest Lifetime (default 4000 msec)
        :param hoplimit: Interest Hop Limit (default 255)
        """
        ccnpy.TlvType.__init__(self, ccnpy.TlvType.T_INTEREST)

        self._name = name
        self._keyidrestr = key_id_restr
        self._conobjhashrestr = con_obj_hash_restr

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass
