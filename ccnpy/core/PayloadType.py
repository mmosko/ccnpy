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

from .Tlv import Tlv
from .TlvType import TlvType


class PayloadType(TlvType):
    __T_PAYLDTYPE = 0x0005
    __T_PAYLOADTYPE_DATA = 0
    __T_PAYLOADTYPE_KEY = 1
    __T_PAYLOADTYPE_LINK = 2
    __T_PAYLOADTYPE_MANIFEST = 3

    __lookup = {__T_PAYLOADTYPE_DATA: "DATA",
                __T_PAYLOADTYPE_KEY: "KEY",
                __T_PAYLOADTYPE_LINK: "LINK",
                __T_PAYLOADTYPE_MANIFEST: "MANIFEST"}

    def __to_string(self):
        if self._payload_type in PayloadType.__lookup:
            return PayloadType.__lookup[self._payload_type]
        else:
            return "Unknown %r" % self._payload_type

    @classmethod
    def class_type(cls):
        return cls.__T_PAYLDTYPE

    def __init__(self, payload_type):
        TlvType.__init__(self)
        self._payload_type = payload_type
        self._tlv = Tlv.create_uint8(self.class_type(), self._payload_type)

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "PLDTYP: %r" % self.__to_string()

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value_as_number())

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def create_data_type(cls):
        return cls(cls.__T_PAYLOADTYPE_DATA)

    @classmethod
    def create_key_type(cls):
        return cls(cls.__T_PAYLOADTYPE_KEY)

    @classmethod
    def create_link_type(cls):
        return cls(cls.__T_PAYLOADTYPE_LINK)

    @classmethod
    def create_manifest_type(cls):
        return cls(cls.__T_PAYLOADTYPE_MANIFEST)

    def is_data(self):
        return self._payload_type == self.__T_PAYLOADTYPE_DATA

    def is_key(self):
        return self._payload_type == self.__T_PAYLOADTYPE_KEY

    def is_link(self):
        return self._payload_type == self.__T_PAYLOADTYPE_LINK

    def is_manifest(self):
        return self._payload_type == self.__T_PAYLOADTYPE_MANIFEST
