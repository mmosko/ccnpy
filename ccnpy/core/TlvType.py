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
from abc import abstractmethod, ABC

from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Serializable import Serializable
from ccnpy.core.Tlv import Tlv
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.exceptions.ParseError import ParseError


class TlvType(Serializable):
    """
    superclass for objects that are TLV types
    """
    def __init__(self):
        pass

    @abstractmethod
    def __len__(self):
        """
        Returns the TLV encoded length
        :return:
        """
        pass

    @classmethod
    @abstractmethod
    def class_type(cls):
        pass

    @abstractmethod
    def serialize(self):
        pass

    @classmethod
    @abstractmethod
    def parse(cls, tlv):
        pass

    @classmethod
    def auto_parse(cls, tlv, name_class_pairs):
        """
        `name_class_pairs` is a list of (str, class) pairs.  The string is the argument name for the
         class constructor and the class is the corresponding TlvType.  `auto_parse` will go through the
        `tlv` nesting and extract out the available classes.  it will then return a dictionary
        `Dict[str, tlvtype]` that is used to initalize the class.

        Example from GroupData:
            classes = [ ('subtree_size', SubtreeSize),
                   ('subtree_digest', SubtreeDigest),
                   ('leaf_size', LeafSize),
                   ('leaf_digest', LeafDigest),
                   ('nc_id', NcId),
                   ('start_segment_id', StartSegmentId) ]

            values = cls.auto_parse(tlv, classes)
            return GroupData(**values)
        """
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        assert tlv.length() == len(tlv.value())
        return cls.auto_value_parse(tlv.value(), name_class_pairs)

    @staticmethod
    def auto_value_parse(tlv_value, name_class_pairs):
        """
        Like `auto_parse`, but only parses the value after we've verified the outer class_type.
        """
        parser_lookup = {y.class_type(): (x, y) for x, y in name_class_pairs}
        values = {x: None for x, y in name_class_pairs}

        offset = 0
        while offset < len(tlv_value):
            try:
                inner_tlv = Tlv.deserialize(tlv_value[offset:])
            except ParseError as e:
                print(f'Error parsing {tlv_value} at offset {offset}: {e}')
                raise

            offset += len(inner_tlv)

            try:
                name_class = parser_lookup[inner_tlv.type()]
                arg_name = name_class[0]
                clazz = name_class[1]
                assert values[arg_name] is None
                values[arg_name] = clazz.parse(inner_tlv)
            except KeyError:
                raise ParseError("Unsupported TLV type %r" % inner_tlv)
        return values


class IntegerTlvType(TlvType, ABC):
    """
    A variable length, big-endian encoded integer.

        Foo = TYPE LENGTH Integer
    """

    def __init__(self, value):
        TlvType.__init__(self)
        self._value = value
        self._tlv = Tlv.create_varint(self.class_type(), self._value)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if not isinstance(other, IntegerTlvType):
            return False
        return self._value == other._value

    def value(self):
        return self._value

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value_as_number())

    def serialize(self):
        return self._tlv.serialize()


class OctetTlvType(TlvType, ABC):
    """Encodes an octet string"""

    def __init__(self, value):
        TlvType.__init__(self)

        if isinstance(value, list):
            value = array.array("B", value)

        self._value = value
        self._tlv = Tlv(self.class_type(), self._value)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if not isinstance(other, OctetTlvType):
            return False
        return self._value == other._value

    def __repr__(self):
        return "%r" % DisplayFormatter.hexlify(self._value)

    def value(self):
        return self._value

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value())
