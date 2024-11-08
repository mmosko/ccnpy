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
from typing import Optional

from ccnpy.core.ExpiryTime import ExpiryTime
from ccnpy.core.Name import Name
from ccnpy.core.Packet import PacketWriter
from ccnpy.crypto.AeadKey import AeadGcm
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256Signer
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.ManifestTree import ManifestTree
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tree.TreeIO import TreeIO


class ManifestWriter:
    """
    """

    def __init__(self, args, packet_writer: PacketWriter):
        """

        :param args:
        :param packet_writer: In testing, we pass our own packet writer, otherwise create one for the directory
        """
        self._filename = args.filename
        self._packet_writer = packet_writer
        self._tree_options = self._create_tree_options(args)

    @staticmethod
    def _create_locator(uri: str) -> Optional[Locators]:
        if uri is not None:
            return Locators.from_uri(uri)
        return None

    @staticmethod
    def _create_name(uri: str) -> Optional[Name]:
        if uri is not None:
            return Name.from_uri(uri)
        return None

    def _create_tree_options(self, args):
        encryptor = None
        if args.enc_key is not None:
            key_bytes = bytearray.fromhex(args.enc_key)
            key = AeadGcm(key_bytes)
            encryptor = AeadEncryptor(key=key, key_number=args.key_num)

        signing_key = RsaKey.load_pem_key(args.key_file, args.key_pass)

        tree_options = ManifestTreeOptions(name=Name.from_uri(args.name),
                                           schema_type=SchemaType.parse(args.schema),
                                           signer=RsaSha256Signer(signing_key),
                                           manifest_prefix=self._create_name(args.manifest_prefix),
                                           data_prefix=self._create_name(args.data_prefix),

                                           manifest_locators=self._create_locator(args.manifest_locator),
                                           data_locators=self._create_locator(args.data_locator),

                                           root_expiry_time=self._parse_time(args.root_expiry),
                                           manifest_expiry_time=self._parse_time(args.node_expiry),
                                           data_expiry_time=self._parse_time(args.data_expiry),

                                           manifest_encryptor=encryptor,

                                           add_node_subtree_size=True,

                                           max_packet_size=args.max_size,
                                           max_tree_degree=args.tree_degree,
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

    @staticmethod
    def _parse_time(value):
        """
        Parses an ISO time to a datetime

        :param value: e.g. '20191011Z010203'
        :return: A datetime object
        """
        if value is None:
            return None
        else:
            return ExpiryTime.from_datetime(datetime.fromisoformat(value))

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
                              tree_options=self._tree_options)

            root_manifest_packet = mt.build()
        return root_manifest_packet


def run():
    max_size = 1500

    parser = argparse.ArgumentParser()
    parser.add_argument('--schema', dest='schema', choices=['Hashed', 'Prefix', 'Segmented'], default='Hashed',
                        help='Name constructor schema (default Hashed)')
    parser.add_argument('--name', dest="name", help='CCNx URI for root manifest', required=True)
    parser.add_argument('--manifest-locator', dest="manifest_locator", default=None,
                        help='CCNx URI for manifest locator')
    parser.add_argument('--data-locator', dest="data_locator", default=None, help='CCNx URI for data locator')
    parser.add_argument('--manifest-prefix', dest="manifest_prefix", help='CCNx URI for manifests (Segmented only)')
    parser.add_argument('--data-prefix', dest="data_prefix", help='CCNx URI for data (Segmented only)')

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
    parser.add_argument('--node-expiry', dest="node_expiry",
                        help="Expiry time (ISO format) to expire node manifests")
    parser.add_argument('--data-expiry', dest="data_expiry",
                        help="Expiry time (ISO format) to expire data nameless objects")

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

    if args.schema == 'Segmented':
        if args.manifest_name is None or args.data_name is None:
            raise ValueError('For SegmentedSchema, must provide --manifest-name and --data-name.')
    elif args.manifest_name is not None or args.data_name is not None:
        raise ValueError('--manifest-name and --data-name only apply to SegmentedSchema.')

    try:
        writer = ManifestWriter(args=args, packet_writer=packet_writer)
        writer.build()
    finally:
        if packet_writer is not None:
            packet_writer.close()


if __name__ == "__main__":
    run()
