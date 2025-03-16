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
import abc
import array
import hashlib
from typing import Iterable, Optional

from .ContentObject import ContentObject
from .FixedHeader import FixedHeader
from .HashValue import HashValue
from .Interest import Interest
from .Name import Name
from .Tlv import Tlv
from .ValidationAlg import ValidationAlg
from .ValidationPayload import ValidationPayload
from ..flic.tlvs.Locators import Locators


class Packet:
    __FIXED_HEADER_LEN = 8

    @classmethod
    def create_interest(cls, body, hop_limit):
        # TODO: Hard-coding the 8 is not good
        fh = FixedHeader.create_interest(packet_length=cls.__FIXED_HEADER_LEN + len(body), hop_limit=hop_limit)
        return cls(header=fh, body=body)

    @classmethod
    def create_content_object(cls, body):
        # TODO: Hard-coding the 8 is not good
        fh = FixedHeader.create_content_object(packet_length=cls.__FIXED_HEADER_LEN + len(body))
        return cls(header=fh, body=body)

    @classmethod
    def create_signed_interest(cls, body, hop_limit, validation_alg, validation_payload):
        # TODO: Hard-coding the 8 is not good
        packet_length = cls.__FIXED_HEADER_LEN + len(body) + len(validation_alg) + len(validation_payload)
        fh = FixedHeader.create_interest(packet_length=packet_length, hop_limit=hop_limit)
        return cls(header=fh, body=body, validation_alg=validation_alg, validation_payload=validation_payload)

    @classmethod
    def create_signed_content_object(cls, body, validation_alg, validation_payload):
        # TODO: Hard-coding the 8 is not good
        packet_length = cls.__FIXED_HEADER_LEN + len(body) + len(validation_alg) + len(validation_payload)
        fh = FixedHeader.create_content_object(packet_length=packet_length)
        return cls(header=fh, body=body, validation_alg=validation_alg, validation_payload=validation_payload)

    def __init__(self, header, body, validation_alg=None, validation_payload=None):
        if not isinstance(header, FixedHeader):
            raise TypeError("header is not FixedHeader")

        if not (isinstance(body, Interest) or isinstance(body, ContentObject)):
            raise TypeError("body is not Interest or ContentObject")

        if validation_alg is not None and not isinstance(validation_alg, ValidationAlg):
            raise TypeError("validation_alg must be ValidationAlg")

        if validation_payload is not None and not isinstance(validation_payload, ValidationPayload):
            raise TypeError("validation_payload must be ValidationPayload")

        if (validation_alg is not None and validation_payload is None) or \
            (validation_alg is None and validation_payload is not None):
            raise TypeError("validation_alg and validation_payload must both be None or not None, not mixed")

        self._header = header
        self._body = body
        self._validation_alg = validation_alg
        self._validation_payload = validation_payload
        self._wire_format = self.__serialize()
        self._hash = self._compute_hash()

    def __serialize(self):
        byte_list = self._header.serialize()
        byte_list.extend(self._body.serialize())
        if self._validation_alg is not None:
            byte_list.extend(self._validation_alg.serialize())
        if self._validation_payload is not None:
            byte_list.extend(self._validation_payload.serialize())
        return array.array("B", byte_list)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "{Packet: {%r, %r, %r, %r}}" % (self._header, self._body, self._validation_alg, self._validation_payload)

    def __len__(self):
        return len(self._wire_format)

    @classmethod
    def deserialize(cls, buffer):
        header = body = val_alg = val_payload = None

        offset = 0
        header = FixedHeader.deserialize(buffer)
        offset += header.header_length()

        while offset < len(buffer):
            tlv = Tlv.deserialize(buffer[offset:])
            offset += len(tlv)

            if tlv.type() == ContentObject.class_type():
                assert body is None
                body = ContentObject.parse(tlv)
            elif tlv.type() == Interest.class_type():
                assert body is None
                body = Interest.parse(tlv)
            elif tlv.type() == ValidationAlg.class_type():
                assert val_alg is None
                val_alg = ValidationAlg.parse(tlv)
            elif tlv.type() == ValidationPayload.class_type():
                assert val_alg is not None
                assert val_payload is None
                val_payload = ValidationPayload.parse(tlv)
            else:
                raise RuntimeError("Unsupported packet TLV type %r" % tlv.type())

        return cls(header=header, body=body, validation_alg=val_alg, validation_payload=val_payload)

    @classmethod
    def load(cls, filename):
        with open(filename, 'rb') as infile:
            return cls.deserialize(array.array("B", infile.read()))

    def serialize(self):
        return self._wire_format

    def save(self, filename):
        with open(filename, 'wb') as outfile:
            outfile.write(self.serialize().tobytes())

    def header(self):
        return self._header

    def body(self):
        return self._body

    def validation_alg(self):
        return self._validation_alg

    def validation_payload(self):
        return self._validation_payload

    def _compute_hash(self):
        h = hashlib.sha256()
        h.update(self.body().serialize())
        if self.validation_alg() is not None:
            h.update(self.validation_alg().serialize())
        if self.validation_payload() is not None:
            h.update(self.validation_payload().serialize())
        digest = h.digest()
        return HashValue.create_sha256(array.array("B", digest))

    def content_object_hash(self):
        return self._hash

class PacketReader(abc.ABC):
    # TODO: We should bake in a validator callback, so the caller can validate received packets vs a trust or keystore.
    @abc.abstractmethod
    def get(self, name: Name, hash_restriction: HashValue, locators: Optional[Locators] = None) -> Packet:
        pass

    def close(self):
        pass

class PacketWriter(abc.ABC):
    @abc.abstractmethod
    def put(self, packet: Packet):
        pass

    def close(self):
        pass
