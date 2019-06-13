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

import ccnpy


class SubtreeDigest(ccnpy.TlvType):
    __type = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, digest):
        ccnpy.TlvType.__init__(self)

        if digest is None:
            raise ValueError("digest must not be None")
        if not isinstance(digest, ccnpy.HashValue):
            raise TypeError("digest must be ccnpy.HashValue")

        self._digest = digest
        self._tlv = ccnpy.Tlv(self.class_type(), self._digest)

    def __repr__(self):
        return "SubtreeDigest(%r)" % self._digest

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        inner_tlv = ccnpy.Tlv.deserialize(tlv.value())
        digest = ccnpy.HashValue.parse(inner_tlv)
        return cls(digest)

    def serialize(self):
        return self._tlv.serialize()
