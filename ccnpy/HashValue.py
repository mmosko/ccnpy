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

import binascii
from array import array

import ccnpy


class HashValue(ccnpy.TlvType):
    __T_SHA_256 = 0x0001

    @classmethod
    def class_type(cls):
        """
        TODO: Need workaround for multiple hash types
        :return:
        """
        return cls.__T_SHA_256

    def __init__(self, hash_algorithm, value):
        """

        :param hash_algorithm: The method used to compute the hash (e.g. T_SHA_256)
        :param value: The hash value
        """
        ccnpy.TlvType.__init__(self)

        if not isinstance(value, array):
            value = array("B", value)

        self._hash_algorithm = hash_algorithm
        self._value = value
        self._tlv = ccnpy.Tlv(hash_algorithm, self._value)
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
        if self._hash_algorithm == self.__T_SHA_256:
            return "SHA256"
        else:
            return "Unknown(%r)" % self._hash_algorithm

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "HashValue: {alg: %r, val: %r}" % (self.__alg_string(), ccnpy.DisplayFormatter.hexlify(self._value))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        # TODO: Inefficient way to get a hash of this array
        return hash(str(self._wire_format))

    def hash_algorithm(self):
        return self._hash_algorithm

    def value(self):
        return self._value

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if not isinstance(tlv, ccnpy.Tlv):
            raise TypeError('tlv must be ccnpy.Tlv')
        return cls(tlv.type(), tlv.value())

    @classmethod
    def deserialize(cls, buffer):
        """
        In some cases, the HashValue is stored inside another TLV, such as
        (KeyId (HashValue type value)).  This convenience function lets one
        do something like this.

        Example:
            keyid = ccnpy.Tlv(T_KEYID, ccnpy.HashValue(1, [2]))
            wire = keyid.serialize()
            keyid2 = ccnpy.Tlv.deserialize(wire)
            hv = ccnpy.HashValue.deserialize(keyid2.value())

        :param buffer:
        :return:
        """
        tlv = ccnpy.Tlv.deserialize(buffer)
        return cls.parse(tlv)

    @classmethod
    def create_sha256(cls, value):
        return cls(cls.__T_SHA_256, value)
