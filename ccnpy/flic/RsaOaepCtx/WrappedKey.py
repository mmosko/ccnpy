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

from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.crypto.AeadKey import AeadKey
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class WrappedKey(TlvType):
    @classmethod
    def class_type(cls):
        return TlvNumbers.T_WRAPPED_KEY

    def __init__(self, key, salt: int):
        """
        :param rsa_key: The public or private key used to encrypt/decrypt the TLV value
        """
        TlvType.__init__(self)

        if salt is not None and (salt < 0 or salt > 0xFFFFFFFF):
            raise ValueError(f'If salt is specified, it must be unsigned 4-byte integer, got: {salt}')

        self._key = key
        self._salt = salt

        value = Tlv.uint32_to_array(self._salt)
        value.extend(self._key)
        self._tlv = Tlv(self.class_type(), value)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return "WrappedKey: {salt: %r, key: %r}" % (self._salt, DisplayFormatter.hexlify(self._key))

    def salt(self):
        return self._salt

    def key(self):
        return self._key

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        if len(tlv) < 20:
            raise ValueError("There must be at least 20 bytes (salt + 128 bit key")

        salt = Tlv.array_to_number(tlv.value()[0:4])
        key = tlv.value()[4:]

        return cls(salt=salt, key=key)
