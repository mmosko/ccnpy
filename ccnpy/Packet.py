# Copyright 2019 Marc Mosko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import ccnpy


class Packet:
    def __init__(self, header, body, validation_alg=None, validation_payload=None):
        self._header = header
        self._body = body
        self._validation_alg = validation_alg
        self._validation_payload = validation_payload

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
