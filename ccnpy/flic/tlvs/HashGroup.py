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

from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class HashGroup(TlvType):

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_HASH_GROUP

    def __init__(self, group_data: Optional[GroupData] = None, pointers: Optional[Pointers] = None):
        """

        :param group_data:
        :param pointers: A list of HashValue
        """
        TlvType.__init__(self)
        self._group_data = group_data
        self._pointers = pointers

        self._tlv = Tlv(self.class_type(), [self._group_data, self._pointers])

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if not isinstance(other, HashGroup):
            return False
        return self._tlv == other._tlv

    def __repr__(self):
        return "HashGroup: {%r, %r}" % (self._group_data, self._pointers)

    def group_data(self):
        return self._group_data

    def pointers(self):
        """

        :return: A list of HashValue
        """
        return self._pointers

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        values = cls.auto_parse(tlv,
                                [('group_data', GroupData),
                                 ('pointers', Pointers)]
                                )
        return cls(**values)
