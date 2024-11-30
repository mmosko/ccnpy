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
import sys
from abc import ABC, abstractmethod

from ccnpy.core.Name import Name
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
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


class StdOutWrapper:
    def __init__(self):
        self._out = sys.stdout

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._out is not None:
            # do not actually close stdout
            self._out = None

    def write(self, value):
        if not isinstance(value, str):
            value = value.tobytes().decode('utf-8', errors='ignore')
        self._out.write(value)

class ManifestNetworkReader(ManifestReader):
    pass


class ManifestDirectoryReader(ManifestReader):
    """
    """

    def __init__(self, args, keystore: InsecureKeystore):
        """

        :param args: the CLI arguments
        :param packet_writer: In testing, we pass our own packet writer, otherwise create one for the directory
        """
        super().__init__()
        self._root_name = Name.from_uri(args.name)
        self._root_hash = args.hash_restriction
        self._dir = args.in_dir
        self._keystore = keystore
        self._reader = TreeIO.PacketDirectoryReader(self._dir)
        self._writer = self._create_writer(args)
        self.debug = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self._writer is not None:
            self._writer.close()
            self._writer = None

    @staticmethod
    def _create_writer(args):
        if args.output_file_name is None:
            # dup so we do not close stdout
            return StdOutWrapper()

        return open(args.output_file_name, 'wb')

    def read(self):
        """
        """
        with self._writer:
            traverser = Traversal(packet_input=self._reader,
                                  data_writer=self._writer,
                                  keystore=self._keystore)
            # this will walk the manifest tree and write the app data to `data_writer`.
            traverser.traverse(root_name=self._root_name, hash_restriction=self._root_hash)

        print()
        print()
        print(f'Finished traversal, {traverser.count()} objects procssed')


def run():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('ccnpy.flic.tree.Traversal').setLevel(logging.DEBUG)
    logging.getLogger('ccnpy.flic.RsaOaepCtx.RsaOaepImpl').setLevel(logging.DEBUG)
    logging.getLogger('ccnpy.crypto.InsecureKeystore').setLevel(logging.DEBUG)

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
