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
from datetime import datetime
import array
import math

import ccnpy
import ccnpy.flic
import ccnpy.flic.tree


class ManifestWriter:
    """
    """

    def __init__(self, args):
        self._name = args.name
        self._tree_degree = args.tree_degree
        self._root_flag = args.root_flag
        self._key_file = args.key_file
        self._max_size = args.max_size
        self._filename = args.filename
        self._out_dir = args.out_dir
        self._locator = args.locator
        self._root_expiry = self._parse_time(args.root_expiry)
        self._node_expiry = self._parse_time(args.node_expiry)
        self._data_expiry = self._parse_time(args.data_expiry)
        self._enc_key = args.enc_key
        self._key_num = args.key_num

        # These are the DirectPointers for the file chunks.
        self._file_chunks = ccnpy.flic.tree.FileChunks()

    def run(self):
        print("Splitting file %r" % self._filename)
        total_file_bytes = self._split_file()
        print("Total data objects %r" % len(self._file_chunks))

        print("Creating manifest tree")
        self._create_manifest_tree()

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

        :return:
        """
        params = ccnpy.flic.tree.TreeParameters(self._file_chunks, self._max_size)

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

    def _split_file(self):
        """
        Splits a file into peices that fit into max_size.  Updates the self._chunks list with the
        content object hash values of each chunk.   Saves each chunk to the file system in the directory
        self._out_dir.

        TODO: Does not save to self._out_dir

        :return: total_file_bytes
        """
        total_file_bytes = 0
        payload_size = self._calculate_nameless_payload_size()
        with open(self._filename, 'rb') as f:
            payload_value = f.read(payload_size)
            total_file_bytes += len(payload_value)
            payload_tlv = ccnpy.Payload(payload_value)
            nameless = ccnpy.ContentObject.create_data(name=None, payload=payload_tlv, expiry_time=self._data_expiry)
            packet = ccnpy.Packet.create_content_object(nameless)
            assert len(packet) <= self._max_size
            co_hash = packet.content_object_hash()
            direct_pointer = ccnpy.flic.SizedPointer(content_object_hash=co_hash, length=len(payload_value))
            self._file_chunks.append(direct_pointer)
            filename = direct_pointer.file_name()
            packet.save(filename)
        return total_file_bytes


if __name__ == "__main__":
    tree_degree = 3
    max_size = 1500

    parser = argparse.ArgumentParser()
    parser.add_argument("-n", dest='name', help="root manifest name URI (e.g. ccnx:/example.com/foo)", required=True)
    parser.add_argument("-d", dest="tree_degree", default=tree_degree, type=int, help='manifest tree degree (default %(default))')
    parser.add_argument('--root', dest="root_flag", action='store_true', help="use a named root manifest with a single pointer to nameless")
    parser.add_argument('-k', dest="key_file", help="RSA private key in PEM format to sign the root manifest")
    parser.add_argument('-s', dest="max_size", type=int, default=max_size, help='maximum content object size (default %(default))')
    parser.add_argument('-o', dest="out_dir", default='.', help="output directory (default=%(default))")
    parser.add_argument('-l', dest="locator", help="URI of a locator (root manifest)")
    parser.add_argument('--root-expiry', dest="root_expiry", help="Expiry time (ISO format, .e.g 2020-12-31T23:59:59+00:00) to expire root manifest")
    parser.add_argument('--node-expiry', dest="node_expiry", help="Expiry time (ISO format) to expire node manifests")
    parser.add_argument('--data-expiry', dest="data_expiry", help="Expiry time (ISO format) to expire data nameless objects")
    parser.add_argument('--enc-key', dest="enc_key", help="AES encryption key (hex string)")
    parser.add_argument('--key-num', dest="key_num", help="Key number of pre-shared key")

    parser.add_argument('filename', help='The filename to split into the manifest')

    args = parser.parse_args()
    print(args)
    writer = ManifestWriter(args)

