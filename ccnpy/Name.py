
from urllib.parse import urlparse
from pathlib import PurePath
import array

import ccnpy


class NameComponent(ccnpy.Tlv):
    def __init__(self, type=ccnpy.TlvType.T_NAMESEGMENT, value=None):
        ccnpy.Tlv.__init__(self, type=type, value=value)

class Name(ccnpy.TlvType):
    def __init__(self, components=None):
        """

        :param components: An array of NameComponents
        """
        ccnpy.TlvType.__init__(self, type_number=ccnpy.TlvType.T_NAME)
        self._components = components
        self._tlv = ccnpy.Tlv(self.type_number(), self._components)

    def __str__(self):
        return "NAME(%r)" % self._components

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
    def deserialize(cls, tlv):
        return cls()

    @classmethod
    def from_uri(cls, uri):
        p = urlparse(uri)
        assert(p.scheme == 'ccnx')
        path = PurePath(p.path)
        components = []
        # The first element of the array is '/', so skip it
        for component in path.parts[1:]:
            a = bytearray(component, 'utf-8')
            c = NameComponent(value=a)
            components.append(c)

        return cls(components)

