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


import hashlib
import array
import ccnpy


class Packet:
    @classmethod
    def create_interest(cls, body, hop_limit):
        fh = ccnpy.FixedHeader.create_interest(packet_length=len(body), hop_limit=hop_limit)
        return cls(header=fh, body=body)

    @classmethod
    def create_content_object(cls, body):
        fh = ccnpy.FixedHeader.create_content_object(packet_length=len(body))
        return cls(header=fh, body=body)

    @classmethod
    def create_signed_interest(cls, body, hop_limit, signer):
        pass


    def __init__(self, header, body, validation_alg=None, validation_payload=None):
        if not isinstance(header, ccnpy.FixedHeader):
            raise TypeError("header is not ccnpy.FixedHeader")

        if not (isinstance(body, ccnpy.Interest) or isinstance(body, ccnpy.ContentObject)):
            raise TypeError("body is not ccnpy.Interest or ccnpy.ContentObject")

        if validation_alg is not None and not isinstance(validation_alg, ccnpy.ValidationAlg):
            raise TypeError("validation_alg must be ccnpy.ValidationAlg")

        if validation_payload is not None and not isinstance(validation_payload, ccnpy.ValidationPayload):
            raise TypeError("validation_payload must be ccnpy.ValidationPayload")

        if (validation_alg is not None and validation_payload is None) or \
            (validation_alg is None and validation_payload is not None):
            raise TypeError("validation_alg and validation_payload must both be None or not None, not mixed")

        self._header = header
        self._body = body
        self._validation_alg = validation_alg
        self._validation_payload = validation_payload
        self._wire_format = self.__serialize()

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
        return "Packet(%r, %r, %r, %r)" % (self._header, self._body, self._validation_alg, self._validation_payload)

    @classmethod
    def deserialize(cls, buffer):
        header = body = val_alg = val_payload = None

        offset = 0
        header = ccnpy.FixedHeader.deserialize(buffer)
        offset += header.header_length()

        while offset < len(buffer):
            tlv = ccnpy.Tlv.deserialize(buffer)
            offset += len(tlv)

            if tlv.type() == ccnpy.TlvType.T_OBJECT:
                assert body is None
                body = ccnpy.ContentObject.deserialize(tlv)
            elif tlv.type() == ccnpy.TlvType.T_INTEREST:
                assert body is None
                body = ccnpy.Interest.deserialize(tlv)
            elif tlv.type() == ccnpy.TlvType.T_VALIDATION_ALG:
                assert val_alg is None
                val_alg = ccnpy.ValidationAlg.deserialize(tlv)
            elif tlv.type() == ccnpy.TlvType.T_VALIDATION_ALG:
                assert val_alg is not None
                assert val_payload is None
                val_payload = ccnpy.ValidationPayload.deserialize(tlv)
            else:
                raise RuntimeError("Unsupported packet TLV type %r" % tlv.type())

        return cls(header=header, body=body, validation_alg=val_alg, validation_payload=val_payload)

    def serialize(self):
        return self._wire_format

    def header(self):
        return self._header

    def body(self):
        return self._body

    def validation_alg(self):
        return self._validation_alg

    def validation_payload(self):
        return self._validation_payload

    def content_object_hash(self):
        h = hashlib.sha256()
        h.update(self.body().serialize())
        if self.validation_alg() is not None:
            h.update(self.validation_alg().serialize())
        if self.validation_payload() is not None:
            h.update(self.validation_payload().serialize())
        digest = h.digest()
        tlv = ccnpy.HashValue.create_sha256(digest)
        return tlv
