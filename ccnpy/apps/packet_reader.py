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
import logging
from pathlib import PurePath

from ccnpy.apps.packet_utils import validate_packet, decrypt_manifest
from ccnpy.core.ContentObject import ContentObject
from ccnpy.core.DisplayFormatter import DisplayFormatter
from ccnpy.core.Packet import Packet
from ccnpy.flic.tlvs.Manifest import Manifest
from .cli_utils import add_encryption_cli_args, aead_decryptor_from_cli_args, fixup_key_password, create_keystore


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
        self._keystore = create_keystore(args)
        self._decryptor=aead_decryptor_from_cli_args(args)
        self._has_rsa_kay = args.key_file is not None

    def _output(self, value):
        if self._prettify:
            print(DisplayFormatter.prettify(value))
        else:
            ContentObject.USE_BRIEF_OUTPUT = True
            print(value)

    def read(self):
        """
        """
        packet = Packet.load(self._path)
        self._output(packet)

        try:
            validate_packet(keystore=self._keystore, packet=packet)
        except KeyError as e:
            print(f'Could not validate packet: {e}')
            return


        if packet.body().is_manifest():
            manifest = Manifest.from_content_object(packet.body())
            # if manifest is not encrypted, we already output in the packet dump, no need to repeat
            if manifest.is_encrypted():
                manifest = decrypt_manifest(keystore=self._keystore, manifest=manifest)
                self._output(manifest)


def run():
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('ccnpy.crypto.InsecureKeystore').setLevel(logging.DEBUG)
    logging.getLogger('ccnpy.apps.cli_utils').setLevel(logging.DEBUG)

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
