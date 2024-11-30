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
from ccnpy.core.HashValue import HashValue
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class Pointers(TlvType):
    """
    Encloses an array of ccnpy.HashValues.

    Note that len(Pointers) will return the TLV wire encoding length.

    You can access Pointers as an array:
        p = Pointers([hv1, hv2, hv3])
        for i in range(0, p.count()):
            hv = p[i]
            print(hv)

    Or you can iterate it:
        p = Pointers([hv1, hv2, hv3])
        for hv in p:
            print(hv)
    """

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_PTRS

    def __init__(self, hash_values):
        TlvType.__init__(self)
        if hash_values is None or not isinstance(hash_values, list):
            raise TypeError("hash_values must be a non-empty list of ccnpy.HashValue")

        self._hash_values = hash_values
        self._tlv = Tlv(self.class_type(), self._hash_values)

    def __len__(self):
        return len(self._hash_values)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "Ptrs: %r" % self._hash_values

    def __getitem__(self, item):
        return self._hash_values[item]

    def __iter__(self):
        self._offset = 0
        return self

    def __next__(self):
        if self._offset == len(self):
            raise StopIteration

        output = self[self._offset]
        self._offset += 1
        return output

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise ValueError("Incorrect TLV type %r" % tlv.type())

        hash_values = []
        offset = 0
        while offset < tlv.length():
            hv = HashValue.deserialize(tlv.value()[offset:])
            offset += len(hv)
            hash_values.append(hv)
        return cls(hash_values)

    def serialize(self):
        return self._tlv.serialize()
