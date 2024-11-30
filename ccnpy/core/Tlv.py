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

import array

from .Serializable import Serializable
from ..exceptions.ParseError import ParseError


class Tlv(Serializable):
    @classmethod
    def create_uint64(cls, tlv_type, value):
        """

        :param tlv_type:
        :param value: Up to an 8-byte number
        :return:
        """
        return cls(tlv_type, Tlv.uint64_to_array(value))

    @classmethod
    def create_uint8(cls, tlv_type, value):
        """

        :param tlv_type:
        :param value: A uint8
        :return:
        """
        assert 0 <= value <= 255
        return cls(tlv_type, Tlv.number_to_array(value))

    @classmethod
    def create_uint16(cls, tlv_type, value):
        """

        :param tlv_type:
        :param value: A uint8
        :return:
        """
        assert 0 <= value <= 0xFFFF
        return cls(tlv_type, Tlv.uint16_to_array(value))

    @classmethod
    def create_varint(cls, tlv_type, value):
        """
        Variable length integer.

        :param tlv_type:
        :param value: Up to an 8-byte number
        :return:
        """
        return cls(tlv_type, Tlv.number_to_array(value))

    def __init__(self, tlv_type, value):
        self._tlv_type = tlv_type
        # If the value is an array, we flatten it here
        self._value = self.flatten(value)
        self._wire_format = self._serialize()

    def __str__(self):
        return "TLV: {T: %r, L: %r, V: %r}" % (self._tlv_type, self.length(), self._value)

    def __repr__(self):
        return "TLV: {T: %r, L: %r, V: %r}" % (self._tlv_type, self.length(), self._value)

    def __len__(self):
        """
        Length of the entire TLV
        :return: 4 + value length
        """
        return 4 + self.length()

    def __iter__(self):
        self._offset = 0
        return self

    def __next__(self):
        if self._offset == len(self._wire_format):
            raise StopIteration

        output = self._wire_format[self._offset]
        self._offset += 1
        return output

    def __eq__(self, other):
        result = False
        if len(self) == len(other):
            if self.value() == other.value():
                result = True

        return result

    def __hash__(self):
        return hash(self._wire_format.tobytes())

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 4:
            raise ParseError("buffer length %r must be at least 4" % len(buffer))

        tlv_type = cls.array_to_number(buffer[0:2])
        length = cls.array_to_number(buffer[2:4])
        value = buffer[4:length + 4]

        if length != len(value):
            raise ParseError(f'TLV length {length} does not match the value length {len(value)}')

        return cls(tlv_type, value)

    @staticmethod
    def flatten(value):
        if isinstance(value, list):
            byte_list = []
            for x in value:
                if x is not None:
                    if isinstance(x, Serializable):
                        byte_list.extend(x.serialize())
                    else:
                        byte_list.append(x)

            return array.array("B", byte_list)
        if value is None:
            return array.array("B", [])
        else:
            return value

    def serialize(self):
        return self._wire_format

    def _serialize(self):
        byte_list = self._encode_type()
        byte_list.extend(self._encode_length())
        byte_list.extend(self.value())

        wire_format = array.array("B", byte_list)
        return wire_format

    def extend(self, other_tlv):
        """
        Create a new TLV that extends this TLV's value() with the other TLV.  Neither the
        current TLV or the other_tlv is modified.

        Example
            a = (Name (Component a)(Component b))
            b = a.extend((Component c)
            # b = (Name (Component a)(Component b)(Component c))

        :param other_tlv:
        :return:
        """
        extension = other_tlv.serialize()
        # make a copy
        new_value = array.array("B", self._value)
        new_value.extend(extension)
        new_tlv = Tlv(self.type(), new_value)
        return new_tlv

    def type(self):
        return self._tlv_type

    def value(self):
        return self._value

    def value_as_number(self):
        return Tlv.array_to_number(self._value)

    def length(self):
        return len(self._value)

    @staticmethod
    def _tlv_encode(uint16):
        return [uint16 >> 8, uint16 & 0xFF]

    def _encode_type(self):
        return self._tlv_encode(self.type())

    def _encode_length(self):
        return self._tlv_encode(self.length())

    @staticmethod
    def number_to_array(n):
        """
        Convert a number to a byte array.  Typically used to add a number
        to a TLV with a variable length.

        :param n: A number
        :return: An array of bytes


        """
        if n < 0x100:
            byte_array = [n]
        elif n < 0x10000:
            byte_array = [n >> 8, n & 0xFF]
        elif n < 0x1000000:
            byte_array = [n >> 16, (n >> 8) & 0xFF, n & 0xFF]
        elif n < 0x100000000:
            byte_array = [n >> 24, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
        else:
            # skip to 8 bytes
            byte_array = [(n >> 56) & 0xFF, (n >> 48) & 0xFF, (n >> 40) & 0xFF, (n >> 32) & 0xFF,
                          (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]

        return array.array("B", byte_array)

    @staticmethod
    def uint64_to_array(n):
        """
        Treat n like an 8-byte number

        :param n:
        :return:
        """
        byte_array = [(n >> 56) & 0xFF, (n >> 48) & 0xFF, (n >> 40) & 0xFF, (n >> 32) & 0xFF,
                      (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
        return array.array("B", byte_array)

    @staticmethod
    def uint32_to_array(n):
        """
        Treat n like an 8-byte number

        :param n:
        :return:
        """
        byte_array = [n >> 24, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]
        return array.array("B", byte_array)

    @staticmethod
    def uint24_to_array(n):
        """
        Treat n like an 3-byte number

        :param n:
        :return:
        """
        byte_array = [n >> 16, (n >> 8) & 0xFF, n & 0xFF]
        return array.array("B", byte_array)

    @staticmethod
    def uint16_to_array(n):
        """
        Treat n like an 2-byte number

        :param n:
        :return:
        """
        assert 0 <= n <= 0xFFFF
        byte_array = [n >> 8, n & 0xFF]
        return array.array("B", byte_array)

    @staticmethod
    def array_to_number(a):
        n = 0
        for b in a:
            n = (n << 8) | b
        return n

