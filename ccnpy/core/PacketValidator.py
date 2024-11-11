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
from typing import Optional

from ccnpy.core.ValidationAlg import ValidationAlg_Crc32c, ValidationAlg_RsaSha256
from ccnpy.crypto.Crc32c import Crc32cVerifier
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.crypto.RsaSha256 import RsaSha256Verifier


class PacketValidator:
    __static_crc32c_verifier = Crc32cVerifier()

    def __init__(self, keystore: Optional[InsecureKeystore]):
        self._keystore = keystore

    def validate_packet(self, packet):
        alg = packet.validation_alg()
        if alg is None:
            return

        if isinstance(alg, ValidationAlg_Crc32c):
            # use a pre-allocated one, no need to allocate every packet
            verifier = self.__static_crc32c_verifier

        elif isinstance(alg, ValidationAlg_RsaSha256):
            if self._keystore is None:
                print(f"Cannot verify packet, no RSA keys.")
                return

            rsa_pub_key = self._keystore.get_rsa(alg.keyid())
            if rsa_pub_key is None:
                print(f"Packet requires RsaSha256 verifier, but no key matching keyid {alg.keyid} found.")
                return

            # TODO: we should cache these
            verifier = RsaSha256Verifier(key=rsa_pub_key)
        else:
            raise ValueError(f'Validation alg {alg} not supported.')

        result = verifier.verify(packet.body().serialize(), alg.serialize(),
                                 validation_payload=packet.validation_payload())
        if not result:
            raise ValueError(f'Packet fails validation')
        print(f"Packet validation success with {verifier}")
        return