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


class ValidationAlg(ccnpy.TlvType):
    def __init__(self, algorithm_id):
        """
        """
        ccnpy.TlvType.__init__(self, algorithm_id)
        pass

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass


class ValidationAlg_Crc32c(ValidationAlg):
    def __init__(self):
        ValidationAlg.__init__(self, ccnpy.TlvType.T_CRC32C)
        self._tlv = ccnpy.Tlv(ccnpy.TlvType.T_VALIDATION_ALG,
                              ccnpy.Tlv(ccnpy.TlvType.T_CRC32C, []))

    @classmethod
    def deserialize(cls, tlv):
        # TODO: Finish
        raise RuntimeError("Not Implemented")

    def serialize(self):
        return self._tlv.serialize()


class ValidationAlg_RsaSha256(ValidationAlg):
    def __init__(self, keyid=None, public_key=None, key_link=None, signature_time=None):
        """
        :param keyid: The keyid to include in the ValidationAlg (HashValue)
        :param public_key: A ccnpy.crypto.RsaKey with a public key to embed in the ValidationAlg (RsaKey)
        :param key_link: A Link to include in the ValidationAlg (Link)
        :param signature_time: A datetime when the signature was created (uses now if None) (SignatureTime)
        """
        ValidationAlg.__init__(self, ccnpy.TlvType.T_RSA_SHA256)

        tlvs = []
        if keyid is None and public_key is not None:
            keyid = public_key.keyid()

        if keyid is None:
            raise ValueError("Must provide a keyid and/or a public_key")

        if keyid is not None:
            tlvs.append(ccnpy.Tlv(ccnpy.TlvType.T_KEYID, keyid))

        if public_key is not None:
            tlvs.append(ccnpy.Tlv(ccnpy.TlvType.T_PUBLICKEY, public_key.keyid()))

        if key_link is not None:
            tlvs.append(ccnpy.Tlv(ccnpy.TlvType.T_KEYLINK, key_link))

        if signature_time is None:
            signature_time = datetime.utcnow()

        if isinstance(signature_time, datetime):
            signature_time = ccnpy.SignatureTime.from_datetime(signature_time)
        elif not isinstance(signature_time, ccnpy.SignatureTime):
            raise TypeError("signature_time must be None (for now), a datetime (UTC), or a ccnpy.SignatureTime")

        tlvs.append(signature_time)
        self._tlv = ccnpy.Tlv(ccnpy.TlvType.T_VALIDATION_ALG,
                              ccnpy.Tlv(ccnpy.TlvType.T_RSA_SHA256, tlvs))

    @classmethod
    def deserialize(cls, tlv):
        # TODO: Finish
        raise RuntimeError("Not Implemented")

    def serialize(self):
        return self._tlv.serialize()
