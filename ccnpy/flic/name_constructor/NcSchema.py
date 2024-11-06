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

from abc import ABC
from typing import Optional

from .ProtocolFlags import ProtocolFlags
from ..Locators import Locators
from ...core.Tlv import Tlv
from ...core.TlvType import TlvType
from ...exceptions.CannotParseError import CannotParseError
from ...exceptions.ParseError import ParseError


class NcSchema(TlvType, ABC):
    """
    Generic supertype of the name constructor schemas
    """
    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @classmethod
    def parse(cls, tlv):
        # To avoid include loops
        subclasses = [InterestDerivedSchema, DataDerivedSchema, PrefixSchema, SegmentedSchema, HashSchema]

        for c in subclasses:
            try:
                return c.parse(tlv)
            except CannotParseError:
                pass

        raise CannotParseError(f'Could not parse as one of {subclasses}')


class ProtocolFlagsSchema(NcSchema, ABC):
    """
    Intermediate supertype for name constructor schemas that have a ProtocolFlags field.
    """
    def __init__(self, flags: Optional[ProtocolFlags] = None):
        NcSchema.__init__(self)
        self._flags = flags
        self._tlv = Tlv(self.class_type(), self._flags)

    def __len__(self):
        return len(self._tlv)

    def serialize(self):
        return self._tlv.serialize()

    def flags(self) -> Optional[ProtocolFlags]:
        return self._flags

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        flags = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            try:
                flags = ProtocolFlags.parse(inner_tlv)
            except CannotParseError:
                raise

        return cls(flags=flags)


class LocatorSchema(ProtocolFlagsSchema, ABC):
    """
    Intermediate supertype for name constructors that have Locators.
    """
    def __init__(self, locators: Locators, flags: Optional[ProtocolFlags] = None):
        NcSchema.__init__(self)
        if locators is None or locators.count() == 0:
            raise ValueError("Locators must be a non-empty list")
        self._flags = flags
        self._locators = locators
        self._tlv = Tlv(self.class_type(), [self._locators, self._flags])

    def __len__(self):
        return len(self._tlv)

    def serialize(self):
        return self._tlv.serialize()

    def locators(self) -> Locators:
        return self._locators

    def count(self):
        """
        The number of locators
        """
        return self._locators.count()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        flags = None
        locators = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ProtocolFlags.class_type():
                flags = ProtocolFlags.parse(inner_tlv)
            elif inner_tlv.type() == Locators.class_type():
                locators = Locators.parse(inner_tlv)
            else:
                raise ParseError(f'Unsupported tlv: {inner_tlv}')

        return cls(locators=locators, flags=flags)


class InterestDerivedSchema(ProtocolFlagsSchema):
    __T_INTEREST_DERIVED_SCHEMA = 0x0001

    @classmethod
    def class_type(cls):
        return cls.__T_INTEREST_DERIVED_SCHEMA

    def __init__(self, flags: Optional[ProtocolFlags] = None):
        ProtocolFlagsSchema.__init__(self, flags)

    def __repr__(self):
        return f"IDS: {self._flags}"


class DataDerivedSchema(ProtocolFlagsSchema):
    __T_DATA_DERIVED_SCHEMA = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__T_DATA_DERIVED_SCHEMA

    def __init__(self, flags: Optional[ProtocolFlags] = None):
        ProtocolFlagsSchema.__init__(self, flags)

    def __repr__(self):
        return f"DDS: {self._flags}"


class PrefixSchema(LocatorSchema):
    __T_PREFIX_SCHEMA = 0x0003

    @classmethod
    def class_type(cls):
        return cls.__T_PREFIX_SCHEMA

    def __init__(self, locators: Locators, flags: Optional[ProtocolFlags] = None):
        LocatorSchema.__init__(self, locators=locators, flags=flags)

    def __repr__(self):
        return f"PS: {self._flags}, {self._locators}"


class SegmentedSchema(LocatorSchema):
    __T_SEGMENTED_SCHEMA = 0x0004

    @classmethod
    def class_type(cls):
        return cls.__T_SEGMENTED_SCHEMA

    def __init__(self, locators: Locators, flags: Optional[ProtocolFlags] = None):
        LocatorSchema.__init__(self, locators=locators, flags=flags)

    def __repr__(self):
        return f"SS: {self._flags}, {self._locators}"


class HashSchema(LocatorSchema):
    """
    In the Hashed schema, the data packets are all nameless objects.
    """

    __T_HASH_SCHEMA = 0x0005

    @classmethod
    def class_type(cls):
        return cls.__T_HASH_SCHEMA

    def __init__(self, locators: Locators, flags: Optional[ProtocolFlags] = None):
        LocatorSchema.__init__(self, locators=locators, flags=flags)

    def __repr__(self):
        return f"SS: {self._flags}, {self._locators}"
