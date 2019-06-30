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

import argparse
import getpass
from datetime import datetime

import ccnpy
import ccnpy.crypto
import ccnpy.flic
import ccnpy.flic.tree
from ccnpy.flic.presharedkey import PresharedKeyEncryptor


class ManifestWriter:
    """
    """

    def __init__(self, args, packet_writer=None):
        """

        :param args:
        :param packet_writer: In testing, we pass our own packet writer, otherwise create one for the directory
        """
        self._name = ccnpy.Name.from_uri(args.name)
        self._max_size = args.max_size
        self._filename = args.filename
        self._locators = None
        if args.locator is not None:
            locator = ccnpy.flic.Locator(link=ccnpy.Link(name=ccnpy.Name.from_uri(args.locator)))
            self._locators = ccnpy.flic.LocatorList([locator])

        if packet_writer is None:
            self._packet_writer = ccnpy.flic.tree.TreeIO.PacketDirectoryWriter(directory=args.out_dir)
        else:
            self._packet_writer = packet_writer

        self._tree_options = self._create_tree_options(args)
        signing_key = ccnpy.crypto.RsaKey.load_pem_key(args.key_file, args.key_pass)
        self._signer = ccnpy.crypto.RsaSha256_Signer(signing_key)

    def _create_tree_options(self, args):
        encryptor = None
        if args.enc_key is not None:
            key_bytes = bytearray.fromhex(args.enc_key)
            key = ccnpy.crypto.AesGcmKey(key_bytes)
            encryptor=PresharedKeyEncryptor(key=key, key_number=args.key_num)

        tree_options = ccnpy.flic.ManifestTreeOptions(root_expiry_time=self._parse_time(args.root_expiry),
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
            mt = ccnpy.flic.ManifestTree(data_input=data_input,
                                         packet_output=self._packet_writer,
                                         root_manifest_name=self._name,
                                         root_manifest_signer=self._signer,
                                         max_packet_size=self._max_size,
                                         tree_options=self._tree_options)

            root_manifest_packet = mt.build()
        return root_manifest_packet

    def _calculate_nameless_payload_size(self):
        """
        Create a nameless object with empty payload and see how much space we have left.
        :return: payload size of each nameless data object
        """
        nameless = ccnpy.ContentObject.create_data(name=None, expiry_time=self._data_expiry, payload=ccnpy.Payload([]))
        packet = ccnpy.Packet.create_content_object(body=nameless)
        if len(packet) >= self._max_size:
            raise ValueError("An empty nameless ContentObject is %r bytes, but max_size is only %r" %
                             (len(packet), self._max_size))

        payload_size = self._max_size - len(packet)
        return payload_size


if __name__ == "__main__":
    tree_degree = 7
    max_size = 1500

    parser = argparse.ArgumentParser()
    parser.add_argument("-n", dest='name', help="root manifest name URI (e.g. ccnx:/example.com/foo)", required=True)
    parser.add_argument("-d", dest="tree_degree", default=tree_degree, type=int, help='manifest tree degree default %r)' % tree_degree)
    parser.add_argument('-k', dest="key_file", default=None, help="RSA private key in PEM format to sign the root manifest")
    parser.add_argument('-p', dest="key_pass", default=None, help="RSA private key password (otherwise will prompt)")
    parser.add_argument('-s', dest="max_size", type=int, default=max_size, help='maximum content object size (default %r)' % max_size)
    parser.add_argument('-o', dest="out_dir", default='.', help="output directory (default=%r)" % '.')
    parser.add_argument('-l', dest="locator", help="URI of a locator (root manifest)")
    parser.add_argument('--root-expiry', dest="root_expiry", help="Expiry time (ISO format, .e.g 2020-12-31T23:59:59+00:00) to expire root manifest")
    parser.add_argument('--node-expiry', dest="node_expiry", help="Expiry time (ISO format) to expire node manifests")
    parser.add_argument('--data-expiry', dest="data_expiry", help="Expiry time (ISO format) to expire data nameless objects")
    parser.add_argument('--enc-key', dest="enc_key", help="AES encryption key (hex string)")
    parser.add_argument('--key-num', dest="key_num", type=int, help="Key number of pre-shared key")

    parser.add_argument('filename', help='The filename to split into the manifest')

    args = parser.parse_args()
    print(args)

    if args.key_pass is None:
        args.key_pass = getpass.getpass(prompt="Private key password")

    if len(args.key_pass) == 0:
        args.key_pass = None

    writer = ManifestWriter(args)
    writer.build()
