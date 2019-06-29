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
from pathlib import PurePath

import ccnpy
import ccnpy.crypto
import ccnpy.flic
import ccnpy.flic.tree
from ccnpy.flic.presharedkey import PresharedKeyDecryptor


class PacketReader:
    """
    """

    def __init__(self, args, packet_writer=None):
        """

        :param args:
        :param packet_writer: In testing, we pass our own packet writer, otherwise create one for the directory
        """
        self._path = PurePath(args.in_dir, args.filename)

        self._decryptor=None
        if args.enc_key is not None:
            key_bytes = bytearray.fromhex(args.enc_key)
            key = ccnpy.crypto.AesGcmKey(key_bytes)
            self._decryptor=PresharedKeyDecryptor(key=key, key_number=args.key_num)

    def read(self):
        """
        """
        packet = ccnpy.Packet.load(self._path)
        print(packet)
        if packet.body().is_manifest():
            manifest = ccnpy.flic.Manifest.from_content_object(packet.body())
            if manifest.is_encrypted():
                if self._decryptor is not None:
                    plaintext = self._decryptor.decrypt_manifest(manifest)
                    print("Decryption successful")
                    print(plaintext)
                else:
                    print("No decryption key provided")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest="in_dir", default='.', help="input directory (default=%r)" % '.')
    parser.add_argument('--enc-key', dest="enc_key", help="AES decryption key (hex string)")
    parser.add_argument('--key-num', dest="key_num", type=int, help="Key number of pre-shared key")

    parser.add_argument('filename', help='The filename to read and display')

    args = parser.parse_args()

    reader = PacketReader(args)
    reader.read()
