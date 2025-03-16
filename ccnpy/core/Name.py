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
from array import array
from pathlib import PurePath
from typing import List, Optional
from urllib.parse import urlparse

from .Tlv import Tlv
from .TlvType import TlvType


class NameComponent(Tlv):
    __T_NAMESEGMENT=0x0001
    __T_IPID=0x0002
    __T_CHUNKID=0x0005
    __T_MANIFESTID=0x0010

    @classmethod
    def chunk_id_type(cls):
        return cls.__T_CHUNKID

    @classmethod
    def manifest_id_type(cls):
        return cls.__T_MANIFESTID

    @classmethod
    def create_name_segment(cls, value):
        return cls(cls.__T_NAMESEGMENT, value)

    @classmethod
    def create_ipid_segment(cls, value):
        return cls(cls.__T_IPID, value)

    @classmethod
    def create_chunk_segment(cls, value: int):
        return cls(cls.__T_CHUNKID, Tlv.number_to_array(value))

    @classmethod
    def create_manifest_id(cls, value: int):
        return cls(cls.__T_MANIFESTID, Tlv.number_to_array(value))

    def __init__(self, tlv_type, value):
        Tlv.__init__(self, tlv_type=tlv_type, value=value)

    def __repr__(self):
        t = self.type()
        if t == NameComponent.__T_CHUNKID:
            return f'ChunkId={Tlv.array_to_number(self.value())}'
        if t == NameComponent.__T_NAMESEGMENT:
            return f'Name={self.value().decode('UTF-8')}'
        if t == NameComponent.__T_MANIFESTID:
            return f'ManifestId={Tlv.array_to_number(self.value())}'
        if t == NameComponent.__T_IPID:
            return f'IPID={self.value()}'
        return super().__repr__()

    def is_name_segment(self):
        return self._tlv_type == self.__T_NAMESEGMENT

    def is_chunk_id_segment(self):
        return self._tlv_type == self.__T_CHUNKID

    def is_manifest_id_segment(self):
        return self._tlv_type == self.__T_MANIFESTID

class Name(TlvType):
    __T_NAME = 0x0000

    @classmethod
    def class_type(cls):
        return cls.__T_NAME

    def __init__(self, components: Optional[List[NameComponent]] = None):
        """

        :param components: An array of NameComponents
        """
        TlvType.__init__(self)
        self._components = components
        self._tlv = Tlv(self.class_type(), self._components)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __str__(self):
        return "NAME: %r" % [f'{c.type()} = {c.value()}' for c in self._components]

    def __repr__(self):
        return "NAME: %r" % self._components

    def __getitem__(self, index):
        """
        returns only the value of the name component TLV as a string
        :param index: Name component value as a UTF-8 string
        :return:
        """
        v = self._components[index].value()
        if isinstance(v, array):
            return v
        else:
            return v.decode('UTF-8')

    def as_uri(self):
        return 'ccnx:/' + '/'.join([f'{c.type()}={c.value()}' for c in self._components])

    def append(self, component: NameComponent):
        """
        Create a new Name by appending the given name component
        """
        if self._components is not None:
            extended = self._components.copy()
        else:
            extended = []
        extended.append(component)
        return Name(extended)

    def append_chunk_id(self, chunk_id: int):
        """
        A convenience function to append a ChunkId name segment
        """
        return self.append(NameComponent.create_chunk_segment(chunk_id))

    def append_manifest_id(self, manifest_id: int):
        """
        A convenience function to append a ChunkId name segment
        """
        return self.append(NameComponent.create_manifest_id(manifest_id))

    def serialize(self):
        return self._tlv.serialize()

    def count(self):
        """
        The number of name components
        :return:
        """
        return len(self._components)

    def component(self, index) -> NameComponent:
        """
        Returns the index name component as its TLV value

        :param index:
        :return:
        """
        assert index >= 0
        return self._components[index]

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        components = []
        offset = 0
        while offset < tlv.length():
            inner_tlv = NameComponent.deserialize(tlv.value()[offset:])
            if len(inner_tlv) == 0:
                raise RuntimeError("Inner TLV length is 0, must be at least 4")
            offset += len(inner_tlv)

            # Convert to a byte array for readability
            converted_tlv = inner_tlv
            try:
                encoded = inner_tlv.value().tobytes()
                converted_tlv = NameComponent(inner_tlv.type(), encoded)
            except RuntimeError:
                pass

            components.append(converted_tlv)

        return cls(components)

    @classmethod
    def from_uri(cls, uri):
        """
        Creates a simple CCNx name from a URI.  It only supports "name segments" and no other
        type of specialized name segment.

        If uri is none, will return None.
        """
        if uri is None:
            return None
        p = urlparse(uri)
        assert(p.scheme == 'ccnx')
        path = PurePath(p.path)
        components = []
        # The first element of the array is '/', so skip it
        for component in path.parts[1:]:
            a = component.encode()
            c = NameComponent.create_name_segment(value=a)
            components.append(c)

        return cls(components)
