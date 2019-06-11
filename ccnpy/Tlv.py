# Copyright 2019 Marc Mosko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import array


class Tlv:
    @classmethod
    def create_uint64(cls, type, value):
        """

        :param type:
        :param value: Up to an 8-byte number
        :return:
        """
        return cls(type, Tlv.uint64_to_array(value))

    def __init__(self, type, value):
        self._type = type
        # If the value is an array, we flatten it here
        self._value = self._flatten(value)
        self._wire_format = self._serialize()

    def __str__(self):
        return "TLV(%r, %r, %r)" % (self._type, self.length(), self._value)

    def __repr__(self):
        return "TLV(%r, %r, %r)" % (self._type, self.length(), self._value)

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

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 4:
            raise RuntimeError("buffer length %r must be at least 4" % len(buffer))

        type = cls.array_to_number(buffer[0:2])
        length = cls.array_to_number(buffer[2:4])
        value = buffer[4:length + 4]

        return cls(type, value)

    @staticmethod
    def _flatten(value):
        if isinstance(value, list):
            byte_list = []
            for x in value:
                if x is not None:
                    byte_list.extend(x.serialize())
            return array.array("B", byte_list)
        else:
            return value

    def serialize(self):
        return self._wire_format

    def _serialize(self):
        byte_list = self._encode_type()
        byte_list.extend(self._encode_length())
        byte_list.extend(self.value())

        #if isinstance(byte_list, self.value()):

        wire_format = array.array("B", byte_list)
        return wire_format

    def type(self):
        return self._type

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
    def array_to_number(a):
        n = 0
        for b in a:
            n = (n << 8) | b
        return n