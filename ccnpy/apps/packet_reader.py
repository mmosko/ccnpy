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

import argparse
from pathlib import PurePath

from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Packet import Packet
from ccnpy.core.ValidationAlg import ValidationAlg_Crc32c, ValidationAlg_RsaSha256
from ccnpy.crypto.Crc32c import Crc32cVerifier
from ccnpy.crypto.DecryptionError import DecryptionError
from ccnpy.crypto.RsaSha256 import RsaSha256Verifier
from ccnpy.flic.tlvs.Manifest import Manifest
from .cli_utils import add_encryption_cli_args, aead_decryptor_from_cli_args, rsa_verifier_from_cli_args, \
    fixup_key_password


class PacketReader:
    """
    """

    def __init__(self, args, packet_writer=None):
        """

        :param args:
        :param packet_writer: In testing, we pass our own packet writer, otherwise create one for the directory
        """
        self._path = PurePath(args.in_dir, args.filename)
        self._prettify = args.prettify

        self._decryptor=aead_decryptor_from_cli_args(args)
        self._verifier = rsa_verifier_from_cli_args(args)

    def _output(self, value):
        if self._prettify:
            print(DisplayFormatter.prettify(value))
        else:
            print(value)

    def read(self):
        """
        """
        packet = Packet.load(self._path)
        self._output(packet)

        try:
            self._validate_packet(packet)
        except RuntimeError as e:
            print(e)
            return

        if packet.body().is_manifest():
            manifest = Manifest.from_content_object(packet.body())
            if manifest.is_encrypted():
                if self._decryptor is not None:
                    try:
                        plaintext = self._decryptor.decrypt_manifest(manifest)
                        print("Decryption successful")
                        self._output(plaintext)
                    except DecryptionError as e:
                        print(f"Failed decryption: {e}")
                else:
                    print("No decryption key provided")

    def _validate_packet(self, packet):
        alg = packet.validation_alg()
        if alg is None:
            print("Packet has no validation algorithm, not validating")
            return

        if isinstance(alg, ValidationAlg_Crc32c):
            verifier = Crc32cVerifier()
        elif isinstance(alg, ValidationAlg_RsaSha256):
            if self._verifier is None:
                print("Packet requires RsaSha256 verifier, but no keyfile specified on CLI.  Not validating.")
                return

            verifier = self._verifier
        else:
            raise ValueError(f'Validation alg {alg} not supported.')

        result = verifier.verify(packet.body().serialize(), alg.serialize(),
                                 validation_payload=packet.validation_payload())
        if not result:
            raise ValueError(f'Packet fails validation')
        print(f"Packet validation success with {verifier}")
        return


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest="in_dir", default='.', help="input directory (default=%r)" % '.')

    add_encryption_cli_args(parser)

    parser.add_argument('--pretty', dest="prettify", action='store_true', help="pretty print the packets")
    parser.add_argument('filename', help='The filename to read and display')

    args = parser.parse_args()
    fixup_key_password(args, ask_for_pass=False)

    reader = PacketReader(args)
    reader.read()


if __name__ == "__main__":
    run()
