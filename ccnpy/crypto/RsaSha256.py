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

from .RsaKey import RsaKey
from .Signer import Signer
from .Verifier import Verifier
from ..core.SignatureTime import SignatureTime
from ..core.ValidationAlg import ValidationAlg_RsaSha256
from ..core.ValidationPayload import ValidationPayload


class RsaSha256Signer(Signer):
    """
    """

    def __init__(self, key):
        """
        """
        if not isinstance(key, RsaKey):
            raise TypeError("key must be ccnpy.crypto.RsaKey")
        if not key.has_private_key():
            raise RuntimeError("key does not hold a private key, cannot sign")

        self._key = key

    def sign(self, *buffers):
        signature = self._key.sign(*buffers)
        payload = ValidationPayload(signature)
        return payload

    def keyid(self):
        return self._key.keyid()

    def validation_alg(self, include_public_key=False, key_link=None, signature_time=None):
        """
        Generate a ValidationAlg for this key.  If `include_public_key` is True, embed the public key in
        the ValidationAlg.  If key_link is a ccnpy.KeyLink, add it to the ValidationAlg.  If signature_time
        is None, use the current UTC time, othewise use the provided signature_time.

        Note: not all signers support all options.

        :param include_public_key: True to embed the signer's public key
        :param key_link: (optional) a ccnpy.KeyLink
        :param signature_time: a datetime or a ccnpy.SignatureTime or None to use current UTC time.
        :return: A ValidationAlg appropriate to the signer
        """
        if signature_time is None:
            signature_time = SignatureTime.now()
        elif isinstance(signature_time, datetime):
            signature_time = SignatureTime.from_datetime(signature_time)

        public_key = None
        if include_public_key:
            public_key = RsaKey(self._key.public_key_pem())

        return ValidationAlg_RsaSha256(keyid=self.keyid(),
                                       public_key=public_key,
                                       key_link=key_link,
                                       signature_time=signature_time)


class RsaSha256Verifier(Verifier):
    def __init__(self, key):
        if not isinstance(key, RsaKey):
            raise TypeError("key must be ccnpy.crypto.RsaKey")
        if not key.has_public_key():
            raise RuntimeError("key does not hold a public key, cannot verify")
        self._key = key

    def __repr__(self):
        return f"RsaSha256Verifier({self._key.keyid()})"

    def verify(self, *buffers, validation_payload):
        """

        :param buffer: The buffer to checksum
        :param validation_payload: The expected result (ValidationPayload TLV)
        :return: True if checksum verified, False otherwise
        """
        if validation_payload is None:
            raise ValueError("validation_payload must not be None")

        result = self._key.verify(*buffers, signature=validation_payload.payload())
        return result
