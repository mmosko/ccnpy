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
from abc import ABC, abstractmethod
from pathlib import PurePath

from ccnpy.apps.packet_utils import validate_packet, decrypt_manifest
from ccnpy.core.Name import Name
from ccnpy.core.Packet import Packet
from ccnpy.crypto.DecryptionError import DecryptionError
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeIO import TreeIO
from .cli_utils import add_encryption_cli_args, fixup_key_password, create_keystore


class ManifestReader(ABC):
    def __init__(self):
        self._output_file = None

    def output(self, payload):
        print(f"output payload {payload}")
        pass

    @abstractmethod
    def read(self):
        pass


class ManifestNetworkReader(ManifestReader):
    pass


class ManifestDirectoryReader(ManifestReader):
    """
    """

    def __init__(self, args, keystore: InsecureKeystore):
        """

        :param args:
        :param packet_writer: In testing, we pass our own packet writer, otherwise create one for the directory
        """
        super().__init__()
        self._root_name = args.name
        self._root_hash = args.hash_restriction
        self._dir = args.in_dir
        self._prettify = args.prettify
        self._keystore = keystore
        self._decryptors = {}
        self._reader = TreeIO.PacketDirectoryReader(self._dir)

    def read(self):
        """
        """
        root_packet = self._reader.get(name=self._root_name, hash_restriction=self._root_hash)
        traverer = Traversal(packet_input=self._reader)
        self.traverse(packet)

    def read_by_name(self, name: Name, hash_restriction):

    def traverse(self, packet: Packet):
        try:
            validate_packet(keystore=self._keystore, packet=packet)
        except RuntimeError as e:
            print(e)
            exit(-2)

        if not packet.body().is_manifest():
            raise RuntimeError('Traverse can only handle manifest packets')

        manifest = Manifest.from_content_object(packet.body())
        manifest = decrypt_manifest(keystore=self._keystore, manifest=manifest)

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





def run():
    parser = argparse.ArgumentParser()

    parser.add_argument('--name', dest="name", default=None, help='CCNx URI for root manifest', required=True)
    parser.add_argument('--hash', dest="hash_restriction", default=None, help='CCNx URI for root manifest', required=False)

    parser.add_argument('-i', dest="in_dir", default='.', help="input directory (default=%r)" % '.')
    parser.add_argument('-T', dest="use_tcp", default=False, action=argparse.BooleanOptionalAction,
                        help="Use TCP to 127.0.0.1:9896")

    add_encryption_cli_args(parser)

    parser.add_argument('--output', dest="output_file_name", default=None, help='Output filename (default stdout)', required=False)
    parser.add_argument('-v', '--verbose', dest="verbose", action='store_true')

    args = parser.parse_args()
    if args.name is None and args.hash_restriction is None:
        print("You must specify at least one of --name or --hash")
        exit(-1)

    fixup_key_password(args, ask_for_pass=False)

    keystore = create_keystore(args)

    if args.use_tcp:
        reader = ManifestNetworkReader(args, keystore)
    else:
        reader = ManifestDirectoryReader(args, keystore)

    reader.read()


if __name__ == "__main__":
    run()
