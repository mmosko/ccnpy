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


from pathlib import PurePath
from urllib.parse import urlparse

import ccnpy


class NameComponent(ccnpy.Tlv):
    __T_NAMESEGMENT=0x0001
    __T_IPID=0x0002

    @classmethod
    def create_name_segment(cls, value):
        return cls(cls.__T_NAMESEGMENT, value)

    @classmethod
    def create_ipid_segment(cls, value):
        return cls(cls.__T_IPID, value)

    def __init__(self, tlv_type, value):
        ccnpy.Tlv.__init__(self, tlv_type=tlv_type, value=value)


class Name(ccnpy.TlvType):
    __T_NAME = 0x0000

    @classmethod
    def class_type(cls):
        return cls.__T_NAME

    def __init__(self, components=None):
        """

        :param components: An array of NameComponents
        """
        ccnpy.TlvType.__init__(self)
        self._components = components
        self._tlv = ccnpy.Tlv(self.class_type(), self._components)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __str__(self):
        return "NAME: %r" % self._components

    def __repr__(self):
        return "NAME: %r" % self._components

    def __getitem__(self, index):
        """
        returns only the value of the name component TLV as a string
        :param index: Name component value as a UTF-8 string
        :return:
        """
        return self._components[index].value().decode('utf-8')

    def serialize(self):
        return self._tlv.serialize()

    def count(self):
        """
        The number of name components
        :return:
        """
        return len(self._components)

    def component(self, index):
        """
        Returns the index name component as its TLV value

        :param index:
        :return:
        """
        return self._components[index]

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        components = []
        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.NameComponent.deserialize(tlv.value()[offset:])
            if len(inner_tlv) == 0:
                raise RuntimeError("Inner TLV length is 0, must be at least 4")
            offset += len(inner_tlv)

            # Convert to a byte array for readability
            converted_tlv = inner_tlv
            try:
                encoded = inner_tlv.value().tobytes()
                converted_tlv = ccnpy.NameComponent(inner_tlv.type(), encoded)
            except RuntimeError:
                pass

            components.append(converted_tlv)

        return cls(components)

    @classmethod
    def from_uri(cls, uri):
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

