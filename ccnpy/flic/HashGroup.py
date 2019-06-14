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

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, group_data=None, pointers=None):
        """

        :param group_data:
        :param pointers: A list of ccnpy.HashValue
        """
        ccnpy.TlvType.__init__(self)
        if group_data is not None and not isinstance(group_data, ccnpy.flic.GroupData):
            raise TypeError("group_data must be ccnpy.flic.GroupData")

        if pointers is None or not isinstance(pointers, ccnpy.flic.Pointers):
            raise ValueError("pointers must not type ccnpy.flic.Pointers")

        self._group_data = group_data
        self._pointers = pointers

        self._tlv = ccnpy.Tlv(self.class_type(), [self._group_data, self._pointers])

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "HashGroup(%r, %r)" % (self._group_data, self._pointers)

    def group_data(self):
        return self._group_data

    def pointers(self):
        return self._pointers

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        group_data = None
        pointers = None

        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ccnpy.flic.GroupData.class_type():
                assert group_data is None
                group_data = ccnpy.flic.GroupData.parse(inner_tlv)
            elif inner_tlv.type() == ccnpy.flic.Pointers.class_type():
                assert pointers is None
                pointers = ccnpy.flic.Pointers.parse(inner_tlv)
            else:
                raise ValueError("Unsupported TLV %r" % inner_tlv)

        return cls(group_data=group_data, pointers=pointers)
