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
import logging

from crc32c import crc32c

from .Verifier import Verifier
from ..core.Tlv import Tlv
from ..core.ValidationAlg import ValidationAlg_Crc32c
from ..core.ValidationPayload import ValidationPayload
from ..crypto.Signer import Signer


class Crc32cSigner(Signer):
    """
    pip install crc32c
    """
    logger = logging.getLogger(__name__)

    def __init__(self):
        """
        No initalization needed for CRC32c
        """
        pass

    def sign(self, *buffers):
        checksum = 0
        for buffer in buffers:
            checksum = crc32c(buffer, checksum)
        payload = ValidationPayload(Tlv.uint32_to_array(checksum))
        self.logger.debug('crc32c: %s', payload)
        return payload

    def keyid(self):
        return None

    def validation_alg(self, include_public_key=False, key_link=None, signature_time=None):
        """
        Does not support any options.

        :param include_public_key: Must be False
        :param key_link: Must be None
        :param signature_time: Must be none
        :return: A ccnpy.ValidationAlg_Crc32c
        """
        assert not include_public_key
        assert key_link is None
        assert signature_time is None
        return ValidationAlg_Crc32c()


class Crc32cVerifier(Verifier):
    """
    pip install crc32c
    """
    def __init__(self):
        """
        no initialization for crc32c
        """
        pass

    def __repr__(self):
        return "Crc32cVerifier()"

    def verify(self, *buffers, validation_payload):
        """

        :param buffer: The buffer to checksum
        :param validation_payload: The expected result (ValidationPayload TLV)
        :return: True if checksum verified, False otherwise
        """
        if validation_payload is None:
            raise ValueError("validation_payload must not be None")

        checksum = 0
        for buffer in buffers:
            checksum = crc32c(buffer, checksum)

        check_payload = ValidationPayload(Tlv.uint32_to_array(checksum))
        return check_payload == validation_payload
