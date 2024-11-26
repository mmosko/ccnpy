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

from abc import abstractmethod
from datetime import datetime, UTC

from .HashValue import HashValue
from .KeyId import KeyId
from .KeyLink import KeyLink
from .SignatureTime import SignatureTime
from .Tlv import Tlv
from .TlvType import TlvType


class ValidationAlg(TlvType):
    """
    ValidationAlg is an abstract intermediate class between TlvType and the concrete
    validation algorithms.
    """
    __T_VALIDATION_ALG = 0x0003

    @classmethod
    def class_type(cls):
        return cls.__T_VALIDATION_ALG

    def __init__(self):
        """
        """
        TlvType.__init__(self)

    @abstractmethod
    def __len__(self):
        pass

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise ValueError("Incorrect TLV type %r" % tlv.type())

        inner_tlv = Tlv.deserialize(tlv.value())

        if inner_tlv.type() == ValidationAlg_RsaSha256.class_type():
            return ValidationAlg_RsaSha256.parse(inner_tlv)

        if inner_tlv.type() == ValidationAlg_Crc32c.class_type():
            return ValidationAlg_Crc32c.parse(inner_tlv)

        raise ValueError("Unsupported ValidationAlg type %r" % tlv.type())

    @abstractmethod
    def serialize(self):
        pass


class ValidationAlg_Crc32c(ValidationAlg):
    __T_CRC32C = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__T_CRC32C

    def __init__(self):
        ValidationAlg.__init__(self)
        self._tlv = Tlv(ValidationAlg.class_type(),
                              Tlv(self.class_type(), []))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "Crc32c: {}"

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != ValidationAlg_Crc32c.class_type():
            raise ValueError("Incorrect TLV type %r" % tlv.type())

        if tlv.length() != 0:
            raise ValueError("Expected length 0, got %r" % tlv.length())

        return cls()

    def serialize(self):
        return self._tlv.serialize()


class ValidationAlg_RsaSha256(ValidationAlg):
    __T_RSA_SHA256 = 0x0004

    __T_PUBLICKEYLOC = 0x000A
    __T_PUBLICKEY = 0x000B


    @classmethod
    def class_type(cls):
        return cls.__T_RSA_SHA256

    def __init__(self, keyid: HashValue=None, public_key=None, key_link=None, signature_time=None):
        """
        :param keyid: The keyid to include in the ValidationAlg (HashValue)
        :param public_key: A crypto.RsaKey with a public key to embed in the ValidationAlg (RsaKey)
        :param key_link: A Link to include in the ValidationAlg (Link)
        :param signature_time: A datetime when the signature was created (uses now if None) (SignatureTime)
        """
        ValidationAlg.__init__(self)

        tlvs = []
        if keyid is None and public_key is not None:
            keyid = public_key.keyid()

        if keyid is None:
            raise ValueError("Must provide a keyid and/or a public_key")

        tlvs.append(KeyId(keyid))

        if public_key is not None:
            tlvs.append(Tlv(self.__T_PUBLICKEY, public_key.der()))

        if key_link is not None:
            tlvs.append(Tlv(KeyLink.class_type(), key_link))

        if signature_time is None:
            signature_time = datetime.now(UTC)

        if isinstance(signature_time, datetime):
            signature_time = SignatureTime.from_datetime(signature_time)
        elif not isinstance(signature_time, SignatureTime):
            raise TypeError("signature_time must be None (for now), a datetime (UTC), or a SignatureTime")

        tlvs.append(signature_time)
        self._tlv = Tlv(ValidationAlg.class_type(),
                              Tlv(self.class_type(), tlvs))
        self._keyid = keyid
        self._public_key = public_key
        self._key_link = key_link
        self._signature_time = signature_time

    def __eq__(self, other):
        if not isinstance(other, ValidationAlg_RsaSha256):
            return False
        return self._tlv == other._tlv

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "RsaSha256: {keyid: %r, pk: %r, keylink: %r, %r}" % \
               (self._keyid, self._public_key, self._key_link, self._signature_time)

    def keyid(self) -> HashValue:
        return self._keyid

    def public_key(self):
        return self._public_key

    def key_link(self):
        return self._key_link

    def signature_time(self):
        return self._signature_time

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != ValidationAlg_RsaSha256.class_type():
            raise ValueError("Incorrect TLV type %r" % tlv.type())

        # Now parse the body for the inner TLVs
        keyid = public_key = key_link = signature_time = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            if inner_tlv.type() == KeyId.class_type():
                keyid_tlv = KeyId.parse(inner_tlv)
                keyid = keyid_tlv.digest()
            elif inner_tlv.type() == SignatureTime.class_type():
                signature_time = SignatureTime.parse(inner_tlv)
            elif inner_tlv.type() == cls.__T_PUBLICKEY:
                der = inner_tlv.value()
                # TODO: convert from DER to Public Key
                raise RuntimeError("Not implemented")
            elif inner_tlv.type() == KeyLink.class_type():
                # TODO: process a LINK type
                raise RuntimeError("Not implemented")
            offset += len(inner_tlv)
        return cls(keyid=keyid, public_key=public_key, key_link=key_link, signature_time=signature_time)

    def serialize(self):
        return self._tlv.serialize()
