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


class HashValue(ccnpy.TlvType):
    def __init__(self, hash_algorithm, value):
        """

        :param hash_algorithm: The method used to compute the hash (e.g. T_SHA_256)
        :param value: The hash value
        """
        ccnpy.TlvType.__init__(self, hash_algorithm)
        self._value = value
        self._tlv = ccnpy.Tlv(self.type_number(), self._value)
        self._wire_format = self._tlv.serialize()

    def __iter__(self):
        self._offset = 0
        return self

    def __next__(self):
        if self._offset == len(self._wire_format):
            raise StopIteration

        output = self._wire_format[self._offset]
        self._offset += 1
        return output

    def __alg_string(self):
        if self.type_number() == ccnpy.TlvType.T_SHA_256:
            return "SHA256"
        else:
            return "Unknown(%r)" % self.type_number()

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "HashValue(%r, %r)" % (self.__alg_string(), self._value)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def hash_algorithm(self):
        return self.type_number()

    def value(self):
        return self._value

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def deserialize(cls, tlv):
        return cls(tlv.type(), tlv.value())

    @classmethod
    def create_sha256(cls, value):
        return cls(ccnpy.TlvType.T_SHA_256, value)
