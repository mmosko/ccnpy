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


from datetime import datetime
from typing import Optional

from .ExpiryTime import ExpiryTime
from .FinalChunkId import FinalChunkId
from .Link import Link
from .Name import Name
from .Payload import Payload
from .PayloadType import PayloadType
from .Tlv import Tlv
from .TlvType import TlvType
from ..exceptions.ParseError import ParseError


class ContentObject(TlvType):
    __T_OBJECT = 0x0002

    USE_BRIEF_OUTPUT = False

    @classmethod
    def class_type(cls):
        return cls.__T_OBJECT

    @classmethod
    def create_data(cls, name: Optional[Name] = None,
                    payload: Optional[Payload | bytes] = None,
                    expiry_time: Optional[datetime] = None,
                    final_chunk_id: Optional[FinalChunkId | int] = None):
        """

        :param name: Name
        :param payload: A byte array (array.array("B", ...)) or Payload
        :param expiry_time: A python datetime
        :param final_chunk_id: The final chunk number, if using chunked names.
        :return: A ContentObject
        """
        payload_type = None

        if payload is not None:
            payload_type = PayloadType.create_data_type()
            if not isinstance(payload, Payload):
                payload = Payload(payload)

        if expiry_time is not None:
            if isinstance(expiry_time, datetime):
                expiry_time = ExpiryTime.from_datetime(expiry_time)
            if not isinstance(expiry_time, ExpiryTime):
                raise TypeError("expiry_time must be ExpiryTime")

        if final_chunk_id is not None:
            if not isinstance(final_chunk_id, FinalChunkId):
                final_chunk_id = FinalChunkId(final_chunk_id)

        return cls(name=name, payload_type=payload_type, payload=payload,
                   expiry_time=expiry_time, final_chunk_id=final_chunk_id)

    @classmethod
    def create_manifest(cls, manifest, name=None, expiry_time=None):
        """

        :param name: Name
        :param manifest: A serializable object to put in the payload
        :param expiry_time: A python datetime
        :return: A ContentObject
        """
        if manifest is None:
            raise ValueError("manifest must not be None")

        payload_type = PayloadType.create_manifest_type()
        payload = Payload(manifest.serialize())

        if expiry_time is not None:
            if not isinstance(expiry_time, datetime):
                raise TypeError("expiry_time must be datetime")
            expiry_time = ExpiryTime.from_datetime(expiry_time)

        return cls(name=name, payload_type=payload_type, payload=payload, expiry_time=expiry_time)

    @classmethod
    def create_link(cls, link: Link, name: Name, expiry_time=None):
        """

        :param link: The object linked to
        :param name: Name
        :param manifest: A serializable object to put in the payload
        :param expiry_time: A python datetime
        :return: A ContentObject
        """
        if link is None:
            raise ValueError("link must not be None")

        if name is None:
            raise ValueError("a link object requires a name.")

        payload_type = PayloadType.create_link_type()
        payload = Payload(link.serialize())

        if expiry_time is not None:
            if not isinstance(expiry_time, datetime):
                raise TypeError("expiry_time must be datetime")
            expiry_time = ExpiryTime.from_datetime(expiry_time)

        return cls(name=name, payload_type=payload_type, payload=payload, expiry_time=expiry_time)

    def __init__(self, name: Optional[Name] = None, payload_type: Optional[PayloadType] = None,
                 payload: Optional[Payload] = None, expiry_time: Optional[ExpiryTime] = None,
                 final_chunk_id: Optional[FinalChunkId] = None):

        TlvType.__init__(self)
        if name is not None:
            if not isinstance(name, Name):
                raise TypeError("Name must be of type Name")

        if payload is not None:
            if not isinstance(payload, Payload):
                raise TypeError("Payload must be of type Payload")

        if payload_type is not None:
            if not isinstance(payload_type, PayloadType):
                raise TypeError("PayloadType must be of type PayloadType")

        self._name = name
        self._payload_type = payload_type
        self._payload = payload
        self._expiry_time = expiry_time
        self._final_chunk_id = final_chunk_id
        self._tlv = Tlv(self.class_type(), [self._name,
                                            self._expiry_time,
                                            self._payload_type,
                                            self._payload,
                                            self._final_chunk_id])

    def __repr__(self):
        if self.is_manifest():
            from ccnpy.flic.tlvs.Manifest import Manifest
            try:
                payload = Manifest.deserialize(self._payload.value())
            except ParseError as e:
                payload = self._payload.value()

        elif self.is_link():
            payload = Link.deserialize(self._payload.value())
        else:
            if self.USE_BRIEF_OUTPUT:
                payload = f'(payload {len(self._payload)} bytes)'
            else:
                payload = self.payload()

        return "CO: {%r, %r, %r, %r, %r}" % (self.name(), self.expiry_time(), self.payload_type(), payload, self._final_chunk_id)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __len__(self):
        """
        The wire format length of the Content Object
        :return:
        """
        return len(self._tlv)

    def name(self):
        return self._name

    def payload_type(self):
        return self._payload_type

    def payload(self):
        return self._payload

    def expiry_time(self):
        return self._expiry_time

    def final_chunk_id(self):
        return self._final_chunk_id

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r must be T_OBJECT")

        name = payload_type = payload = expiry_time = final_chunk_id = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == Name.class_type():
                assert name is None
                name = Name.parse(inner_tlv)
            elif inner_tlv.type() == PayloadType.class_type():
                assert payload_type is None
                payload_type = PayloadType.parse(inner_tlv)
            elif inner_tlv.type() == Payload.class_type():
                assert payload is None
                payload = Payload.parse(inner_tlv)
            elif inner_tlv.type() == ExpiryTime.class_type():
                assert expiry_time is None
                expiry_time = ExpiryTime.parse(inner_tlv)
            elif inner_tlv.type() == FinalChunkId.class_type():
                assert final_chunk_id is None
                final_chunk_id = FinalChunkId.parse(inner_tlv)
            else:
                raise ValueError("Unsupported ContentObject TLV %r" % inner_tlv.type())

        return cls(name=name, payload_type=payload_type, payload=payload, expiry_time=expiry_time, final_chunk_id=final_chunk_id)

    def serialize(self):
        return self._tlv.serialize()

    @staticmethod
    def is_content_object():
        return True

    def is_manifest(self):
        return self.is_content_object() and self._payload_type is not None and self._payload_type.is_manifest()

    def is_link(self):
        return self.is_content_object() and self._payload_type is not None and self._payload_type.is_link()

    @staticmethod
    def is_interest():
        return False
