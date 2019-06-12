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

from crc32c import crc32
import ccnpy
from ccnpy.crypto import Signer, Verifier


class Crc32c_Signer(Signer):
    """
    pip install crc32c
    """

    def __init__(self):
        """
        No initalization needed for CRC32c
        """
        pass

    def sign(self, buffer):
        checksum = crc32(buffer)
        payload = ccnpy.ValidationPayload(ccnpy.Tlv.uint32_to_array(checksum))
        return payload

    def keyid(self):
        return None


class Crc32c_Verifier(Verifier):
    """
    pip install crc32c
    """
    def __init__(self):
        """
        no initialization for crc32c
        """
        pass

    def verify(self, buffer, validation_payload):
        """

        :param buffer: The buffer to checksum
        :param validation_payload: The expected result (ValidationPayload TLV)
        :return: True if checksum verified, False otherwise
        """
        if validation_payload is None:
            raise ValueError("validation_payload must not be None")

        checksum = crc32(buffer)
        check_payload = ccnpy.ValidationPayload(ccnpy.Tlv.uint32_to_array(checksum))
        return check_payload == validation_payload
