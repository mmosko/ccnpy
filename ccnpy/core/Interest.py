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
from .Tlv import Tlv
from .TlvType import TlvType


class Interest(TlvType):
    __T_INTEREST = 0x0001

    @classmethod
    def class_type(cls):
        return cls.__T_INTEREST

    def __init__(self, name=None, key_id_restr=None, con_obj_hash_restr=None):
        """

        :param name:
        :param key_id_restr: KeyId Restriction
        :param con_obj_hash_restr: Content Object Hash Restriction
        """
        TlvType.__init__(self)

        self._name = name
        self._keyidrestr = key_id_restr
        self._conobjhashrestr = con_obj_hash_restr
        self._tlv = Tlv(self.class_type(), [self._name, self._keyidrestr, self._conobjhashrestr])

    def __len__(self):
        """
        The wire format length of the Interest
        :return:
        """
        return len(self._tlv)

    @classmethod
    def parse(cls, tlv):
        pass

    def serialize(self):
        pass

    @staticmethod
    def is_content_object():
        return False

    @staticmethod
    def is_interest():
        return True
