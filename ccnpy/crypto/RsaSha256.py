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
from ccnpy.crypto import Signer, Verifier, RsaKey


class RsaSha256_Signer(Signer):
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

    def sign(self, buffer):
        signature = self._key.sign(buffer)
        payload = ccnpy.ValidationPayload(signature)
        return payload


class RsaSha256_Verifier(Verifier):
    def __init__(self, key):
        if not isinstance(key, RsaKey):
            raise TypeError("key must be ccnpy.crypto.RsaKey")
        if not key.has_public_key():
            raise RuntimeError("key does not hold a public key, cannot verify")
        self._key = key

    def verify(self, buffer, validation_payload):
        """

        :param buffer: The buffer to checksum
        :param validation_payload: The expected result (ValidationPayload TLV)
        :return: True if checksum verified, False otherwise
        """
        if validation_payload is None:
            raise ValueError("validation_payload must not be None")

        result = self._key.verify(buffer, validation_payload.payload())
        return result
