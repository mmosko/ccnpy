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
import ccnpy.flic


class HashGroup(ccnpy.TlvType):
    __type = 0x0002

    @staticmethod
    def class_type():
        return HashGroup.__type

    def __init__(self, group_data=None, pointers=None):
        """

        :param group_data:
        :param pointers:
        """
        ccnpy.TlvType.__init__(self, self.class_type())
        if group_data is not None and not isinstance(group_data, ccnpy.flic.GroupData):
            raise TypeError("group_data must be ccnpy.flic.GrouData")

        if pointers is None:
            raise ValueError("pointers must not be None")

        if not isinstance(pointers, list) or len(pointers) == 0:
            raise TypeError("pointers must be a list of one or more ccnpy.HashValue")

        self._group_data = group_data
        self._pointers = pointers

        inner_tlvs = [self._group_data]
        inner_tlvs.extend(self._pointers)
        self._tlv = ccnpy.Tlv(self.type_number(), inner_tlvs)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return "HashGroup(%r, %r)" % (self._group_data, self._pointers)

    def group_data(self):
        return self._group_data

    def pointers(self):
        return self._pointers

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def deserialize(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        group_data = None
        pointers = []

        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if tlv.type() == ccnpy.flic.GroupData.class_type():
                assert group_data is None
                group_data = ccnpy.flic.GroupData.deserialize(inner_tlv)
            else:
                hash_value = ccnpy.HashValue.deserialize(inner_tlv)
                pointers.append(hash_value)

        return cls(group_data=group_data, pointers=pointers)
