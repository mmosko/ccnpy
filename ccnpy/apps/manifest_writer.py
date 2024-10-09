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
import getpass
from datetime import datetime

from ccnpy.core.Name import Name
from ccnpy.core.Link import Link
from ccnpy.core.Packet import PacketWriter
from ccnpy.crypto.AeadKey import AeadGcm
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256_Signer
from ccnpy.flic.Locator import Locator
from ccnpy.flic.Locators import Locators
from ccnpy.flic.ManifestTree import ManifestTree
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.tree.TreeIO import TreeIO


class ManifestWriter:
    """
    """

    def __init__(self, args, packet_writer: PacketWriter):
        """

        :param args:
        :param packet_writer: In testing, we pass our own packet writer, otherwise create one for the directory
        """
        self._name = Name.from_uri(args.name)
        self._max_size = args.max_size
        self._filename = args.filename
        self._locators = None
        if args.locator is not None:
            locator = Locator(link=Link(name=Name.from_uri(args.locator)))
            self._locators = Locators([locator])

        self._packet_writer = packet_writer

        self._tree_options = self._create_tree_options(args)
        signing_key = RsaKey.load_pem_key(args.key_file, args.key_pass)
        self._signer = RsaSha256_Signer(signing_key)

    def _create_tree_options(self, args):
        encryptor = None
        if args.enc_key is not None:
            key_bytes = bytearray.fromhex(args.enc_key)
            key = AeadGcm(key_bytes)
            encryptor = AeadEncryptor(key=key, key_number=args.key_num)

        tree_options = ManifestTreeOptions(root_expiry_time=self._parse_time(args.root_expiry),
                                           manifest_expiry_time=self._parse_time(args.node_expiry),
                                           data_expiry_time=self._parse_time(args.data_expiry),
                                           manifest_encryptor=encryptor,
                                           add_node_subtree_size=True,
                                           max_tree_degree=args.tree_degree,
                                           root_locators=self._locators,
                                           debug=False)
        return tree_options

    def build(self):
        """

        :return: The root manifest ccnpy.Packet
        """
        print("Creating manifest tree")
        packet = self._create_manifest_tree()
        print("Root manifest hash: %r" % packet.content_object_hash())
        return packet

    def _parse_time(self, value):
        """
        Parses an ISO time to a datetime

        :param value: e.g. '20191011Z010203'
        :return: A datetime object
        """
        if value is None:
            return None
        else:
            return datetime.fromisoformat(value)

    def _create_manifest_tree(self):
        """
        Builds the tree from the end to the beginning so we can link all the manifests together as we
        build the tree.  This means if the tree is unbalanced, it will be unbalanced on the left side.

        :return: The root manifest ccnpy.Packet
        """
        root_manifest_packet = None
        with open(self._filename, 'rb') as data_input:
            mt = ManifestTree(data_input=data_input,
                              packet_output=self._packet_writer,
                              root_manifest_name=self._name,
                              root_manifest_signer=self._signer,
                              max_packet_size=self._max_size,
                              tree_options=self._tree_options)

            root_manifest_packet = mt.build()
        return root_manifest_packet


def run():
    max_size = 1500

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="tree_degree", type=int,
                        help='manifest tree degree (default is max that fits in a packet)')

    parser.add_argument('-k', dest="key_file", default=None,
                        help="RSA private key in PEM format to sign the root manifest")
    parser.add_argument('-p', dest="key_pass", default=None,
                        help="RSA private key password (otherwise will prompt)")

    parser.add_argument('--enc-key', dest="enc_key", default=None, help="AES encryption key (hex string)")
    parser.add_argument('--key-num', dest="key_num", type=int, default=None,
                        help="Key number of pre-shared key (defaults to key hash)")

    parser.add_argument('-s', dest="max_size", type=int, default=max_size,
                        help='maximum content object size (default %r)' % max_size)

    parser.add_argument('-o', dest="out_dir", default='.', help="output directory (default=%r)" % '.')

    parser.add_argument('-T', dest="use_tcp", default=False, action=argparse.BooleanOptionalAction,
                        help="Use TCP to 127.0.0.1:9896")

    parser.add_argument('--root-expiry', dest="root_expiry",
                        help="Expiry time (ISO format, .e.g 2020-12-31T23:59:59+00:00) to expire root manifest")
    parser.add_argument('--node-expiry', dest="node_expiry", help="Expiry time (ISO format) to expire node manifests")
    parser.add_argument('--data-expiry', dest="data_expiry",
                        help="Expiry time (ISO format) to expire data nameless objects")

    subparsers = parser.add_subparsers(title='Schema Modes', dest='schema_mode', help='subcommand help')

    parser_hashed = subparsers.add_parser('HashSchema', help='Hash Schema nameless object mode')
    parser_hashed.add_argument('--root-name', dest="root_name", help='CCNx URI for root manifest', required=True)
    parser_hashed.add_argument('--manifest-locator', dest="manifest_locator", default=None, help='CCNx URI for manifest locator')
    parser_hashed.add_argument('--data-locator', dest="data_locator", default=None, help='CCNx URI for data locator')

    parser_prefix = subparsers.add_parser('PrefixSchema', help='Single Prefix schema')
    parser_prefix.add_argument('--name', dest="root_name", help='CCNx URI for all objects', required=True)
    parser_prefix.add_argument('--manifest-locator', dest="manifest_locator", default=None, help='CCNx URI for manifest locator')
    parser_prefix.add_argument('--data-locator', dest="data_locator", default=None, help='CCNx URI for data locator')

    parser_segmented = subparsers.add_parser('SegmentedSchema', help='Segmented schema')
    parser_segmented.add_argument('--root-name', dest="root_name", help='CCNx URI for root manifest', required=True)
    parser_segmented.add_argument('--manifest-name', dest="manifest_name", help='CCNx URI for manifests', required=True)
    parser_segmented.add_argument('--data-name', dest="data_name", help='CCNx URI for data', required=True)
    parser_segmented.add_argument('--manifest-locator', dest="manifest_locator", default=None, help='CCNx URI for manifest locator')
    parser_segmented.add_argument('--data-locator', dest="data_locator", default=None, help='CCNx URI for data locator')

    parser.add_argument('filename', help='The filename to split into the manifest')

    args = parser.parse_args()
    print(args)

    if args.key_pass is None:
        args.key_pass = getpass.getpass(prompt="Private key password")

    if len(args.key_pass) == 0:
        args.key_pass = None

    if args.enc_key is not None and args.key_num is None:
        # TODO: use something like the left 8 bytes of a sha256
        args.key_num = hash(args.enc_key)

    if args.use_tcp:
        packet_writer = TreeIO.PacketNetworkWriter("127.0.0.1", 9896)
    else:
        packet_writer = TreeIO.PacketDirectoryWriter(directory=args.out_dir)

    try:
        writer = ManifestWriter(args=args, packet_writer=packet_writer)
        writer.build()
    finally:
        if packet_writer is not None:
            packet_writer.close()


if __name__ == "__main__":
    run()
