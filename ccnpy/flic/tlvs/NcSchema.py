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
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.exceptions.ParseError import ParseError
from .SuffixComponentType import SuffixComponentType
from ...core.Name import Name, NameComponent


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
        self._flags = flags
        super().__init__()
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
        self._locators = locators
        super().__init__(flags)
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
        if self._locators is None:
            return 0
        else:
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

class NamedSchema(LocatorSchema, ABC):
    """
    Intermediate supertype for name constructors that have Locators.
    """
    def __init__(self, name: Name, locators: Optional[Locators], flags: Optional[ProtocolFlags] = None):
        self._name = name
        super().__init__(locators=locators, flags=flags)
        self._tlv = Tlv(self.class_type(), [self._name, self._locators, self._flags])

    def __len__(self):
        return len(self._tlv)

    def serialize(self):
        return self._tlv.serialize()

    def name(self) -> Name:
        return self._name

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        flags = locators = name = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ProtocolFlags.class_type():
                flags = ProtocolFlags.parse(inner_tlv)
            elif inner_tlv.type() == Locators.class_type():
                locators = Locators.parse(inner_tlv)
            elif inner_tlv.type() == Name.class_type():
                name = Name.parse(inner_tlv)
            else:
                raise ParseError(f'Unsupported tlv: {inner_tlv}')

        return cls(name=name, locators=locators, flags=flags)

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


class PrefixSchema(NamedSchema):
    __T_PREFIX_SCHEMA = 0x0003

    @classmethod
    def class_type(cls):
        return cls.__T_PREFIX_SCHEMA

    def __init__(self, name: Name, locators: Optional[Locators] = None, flags: Optional[ProtocolFlags] = None):
        super().__init__(name=name, locators=locators, flags=flags)

    def __repr__(self):
        return f"PS: {self._name}, {self._locators}, {self._flags}"

    def __eq__(self, other):
        if not isinstance(other, PrefixSchema):
            return False
        return self._tlv == other._tlv


class SegmentedSchema(NamedSchema):
    __T_SEGMENTED_SCHEMA = 0x0004

    @classmethod
    def class_type(cls):
        return cls.__T_SEGMENTED_SCHEMA

    @classmethod
    def create_for_manifest(cls, name: Name, locators: Optional[Locators] = None, flags: Optional[ProtocolFlags] = None):
        return cls(name=name, locators=locators, flags=flags, suffix_type=SuffixComponentType(NameComponent.manifest_id_type()))

    @classmethod
    def create_for_data(cls, name: Name, locators: Optional[Locators] = None, flags: Optional[ProtocolFlags] = None):
        return cls(name=name, locators=locators, flags=flags, suffix_type=SuffixComponentType(NameComponent.chunk_id_type()))

    def __init__(self, name: Name, suffix_type: SuffixComponentType, locators: Optional[Locators] = None, flags: Optional[ProtocolFlags] = None):
        super().__init__(name=name, locators=locators, flags=flags)
        self._suffix_type = suffix_type
        self._tlv = Tlv(self.class_type(), [self._name, self._suffix_type , self._locators, self._flags])


    def __repr__(self):
        return f"(SS: {self._name}, {self._suffix_type}, {self._locators}, {self._flags})"

    def suffix_type(self) -> SuffixComponentType:
        return self._suffix_type

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv)

        flags = locators = name = suffix_type = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ProtocolFlags.class_type():
                flags = ProtocolFlags.parse(inner_tlv)
            elif inner_tlv.type() == Locators.class_type():
                locators = Locators.parse(inner_tlv)
            elif inner_tlv.type() == Name.class_type():
                name = Name.parse(inner_tlv)
            elif inner_tlv.type() == SuffixComponentType.class_type():
                suffix_type = SuffixComponentType.parse(inner_tlv)
            else:
                raise ParseError(f'Unsupported tlv: {inner_tlv}')

        return cls(name=name, suffix_type=suffix_type, locators=locators, flags=flags)

class HashSchema(LocatorSchema):
    """
    In the Hashed schema, the data packets are all nameless objects.
    """

    __T_HASH_SCHEMA = 0x0005

    @classmethod
    def class_type(cls):
        return cls.__T_HASH_SCHEMA

    def __init__(self, locators: Locators, flags: Optional[ProtocolFlags] = None):
        super().__init__(locators=locators, flags=flags)

    def __repr__(self):
        return f"HS: {self._locators}, {self._flags}"
