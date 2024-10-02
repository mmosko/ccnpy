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
import struct

from .DisplayFormatter import DisplayFormatter


class FixedHeader:
    PT_INTEREST = 0x00
    PT_CONTENT = 0x01
    PT_RETURN = 0x02
    zero_fields = array.array("B", [0, 0, 0])

    def __init__(self, ver=1, packet_type=0, packet_length=8, fields=None, header_length=8):
        """

        :param ver:
        :param packet_type:
        :param packet_length:
        :param fields: A 3-byte UINT8 array corresponding to the 3 bytes of header space
        :param header_length:
        """
        if fields is None:
            fields = FixedHeader.zero_fields

        if isinstance(fields, list):
            fields = array.array("B", fields)

        self._ver = ver
        self._packet_type = packet_type
        self._packet_length = packet_length
        self._fields = fields
        self._header_length = header_length

    def __repr__(self):
        return "FH: {ver: %r, pt: %r, plen: %r, flds: %r, hlen: %r}" % \
               (self._ver, self._packet_type, self._packet_length,
                DisplayFormatter.hexlify(self._fields), self._header_length)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def version(self):
        return self._ver

    def is_interest(self):
        return self._packet_type == FixedHeader.PT_INTEREST

    def is_content_object(self):
        return self._packet_type == FixedHeader.PT_CONTENT

    def is_interest_return(self):
        return self._packet_type == FixedHeader.PT_RETURN

    def packet_length(self):
        return self._packet_length

    def header_length(self):
        return self._header_length

    def serialize(self):
        buffer = struct.pack('!BBHBBBB',
                             self._ver,
                             self._packet_type,
                             self._packet_length,
                             self._fields[0],
                             self._fields[1],
                             self._fields[2],
                             self._header_length)
        return array.array("B", buffer)

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 8:
            raise RuntimeError("buffer less than 8 bytes")

        ver = buffer[0]
        packet_type = buffer[1]
        packet_length = struct.unpack_from('!H', buffer, 2)[0]
        fields = array.array("B", buffer[4:7])
        header_length = buffer[7]

        if ver != 1:
            raise ValueError("fixed header version %r must be 1" % ver)

        if packet_length < 8:
            raise ValueError("packet_length %r must be at least 8" % packet_length)

        if header_length < 8:
            raise ValueError("header_length %r must be at least 8" % header_length)

        return cls(ver=ver, packet_type=packet_type, packet_length=packet_length, fields=fields,
                   header_length=header_length)

    @classmethod
    def create_interest(cls, packet_length, hop_limit):
        return cls(packet_type=cls.PT_INTEREST, packet_length=packet_length, fields=[hop_limit, 0, 0])

    @classmethod
    def create_content_object(cls, packet_length):
        return cls(packet_type=cls.PT_CONTENT, packet_length=packet_length)
