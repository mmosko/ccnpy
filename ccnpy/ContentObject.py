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

from datetime import datetime

import ccnpy


class ContentObject(ccnpy.TlvType):
    __T_OBJECT = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__T_OBJECT

    @classmethod
    def create_data(cls, name=None, payload=None, expiry_time=None):
        """

        :param name: ccnpy.Name
        :param payload: A byte array (array.array("B", ...)) or ccnpy.Payload
        :param expiry_time: A python datetime
        :return: A ccnpy.ContentObject
        """
        payload_type = None

        if payload is not None:
            payload_type = ccnpy.PayloadType.create_data_type()
            if not isinstance(payload, ccnpy.Payload):
                payload = ccnpy.Payload(payload)

        if expiry_time is not None:
            if not isinstance(expiry_time, datetime):
                raise TypeError("expiry_time must be datetime")
            expiry_time = ccnpy.ExpiryTime.from_datetime(expiry_time)
        return cls(name=name, payload_type=payload_type, payload=payload, expiry_time=expiry_time)

    @classmethod
    def create_manifest(cls, manifest, name=None, expiry_time=None):
        """

        :param name: ccnpy.Name
        :param manifest: A serializable object to put in the payload
        :param expiry_time: A python datetime
        :return: A ccnpy.ContentObject
        """
        if manifest is None:
            raise ValueError("manifest must not be None")

        payload_type = ccnpy.PayloadType.create_manifest_type()
        payload = ccnpy.Payload(manifest.serialize())

        if expiry_time is not None:
            if not isinstance(expiry_time, datetime):
                raise TypeError("expiry_time must be datetime")
            expiry_time = ccnpy.ExpiryTime.from_datetime(expiry_time)
        return cls(name=name, payload_type=payload_type, payload=payload, expiry_time=expiry_time)

    def __init__(self, name=None, payload_type=None, payload=None, expiry_time=None):
        ccnpy.TlvType.__init__(self)
        if name is not None:
            if not isinstance(name, ccnpy.Name):
                raise TypeError("Name must be of type ccnpy.Name")

        if payload is not None:
            if not isinstance(payload, ccnpy.Payload):
                raise TypeError("Payload must be of type ccnpy.Payload")

        if payload_type is not None:
            if not isinstance(payload_type, ccnpy.PayloadType):
                raise TypeError("PayloadType must be of type ccnpy.PayloadType")

        self._name = name
        self._payload_type = payload_type
        self._payload = payload
        self._expiry_time = expiry_time
        self._tlv = ccnpy.Tlv(self.class_type(), [self._name,
                                                  self._expiry_time,
                                                  self._payload_type,
                                                  self._payload])

    def __repr__(self):
        if self.is_manifest():
            from ccnpy.flic import Manifest
            payload = Manifest.deserialize(self._payload.value())
        else:
            payload = self.payload()

        return "CO: {%r, %r, %r, %r}" % (self.name(), self.expiry_time(), self.payload_type(), payload)

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

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r must be T_OBJECT")

        name = payload_type = payload = expiry_time = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ccnpy.Name.class_type():
                assert name is None
                name = ccnpy.Name.parse(inner_tlv)
            elif inner_tlv.type() == ccnpy.PayloadType.class_type():
                assert payload_type is None
                payload_type = ccnpy.PayloadType.parse(inner_tlv)
            elif inner_tlv.type() == ccnpy.Payload.class_type():
                assert payload is None
                payload = ccnpy.Payload.parse(inner_tlv)
            elif inner_tlv.type() == ccnpy.ExpiryTime.class_type():
                assert expiry_time is None
                expiry_time = ccnpy.ExpiryTime.parse(inner_tlv)
            else:
                raise ValueError("Unsupported ContentObject TLV %r" % inner_tlv.type())

        return cls(name=name, payload_type=payload_type, payload=payload, expiry_time=expiry_time)

    def serialize(self):
        return self._tlv.serialize()

    @staticmethod
    def is_content_object():
        return True

    def is_manifest(self):
        return self.is_content_object() and self._payload_type is not None and self._payload_type.is_manifest()

    @staticmethod
    def is_interest():
        return False
