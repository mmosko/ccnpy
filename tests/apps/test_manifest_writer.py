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

import os
import tempfile
import unittest
from array import array

from ccnpy.apps.manifest_writer import ManifestWriter
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeIO import TreeIO


class ManifestWriterTest(unittest.TestCase):
    private_key = b'''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA7QdUuaoTr4gA1bMoCdjUNPqpb7f211TYFcahHhaBPnBwQwYj
NIV1HUmKnJiLn59F36iZFYgNR53O30F7g0/oR2MWVaJoeSKq7UP7gqlSjrplZEaI
Yx1MvFKjWAHRDsVTdPNGKqNt8wFZgzxTZw24IlBIk0hOXlgV70TIbo9TvZ9Wl7nI
Uihz66OmY1b+DEokjphEjzX1PJK/a/Xat4L0CRnUVSZ+VGbaqbzkT1FKHTfCVSk6
Jcz7/EtcKnKyajCVcQKoL8Zgv4oXqWzXcGJKewM/87c2S2qMwdocG0XZx90GqEI9
Jk+Rs6JKJoYf9GTW6yDBAH+wGISSPQj0U2GyYwIDAQABAoIBABtFIKZLvwAO8amk
dxLK838055GG5MtZY5L9y0Oe6ze3z/KmHh7Iy/SWpW/mzQmMVYmp6BLmGEEJEuf0
rLUq2Fp+N++aQ9LL/kZV7/XUbT8misvCoaZllJKGH2zcqKS+Zx+pbYUyUFAI87d5
lU7h8TFhczgetYV9NOjWTQkLTGMgXTNiOLraoXqTcO7jB5IrtAtewrImiI7q5a4L
nE03hs2u19iWHPkGvdt7fSMJ66Krju15Afe25Qxwf7n02yJkFcRxa30YGfL3MkMM
wEyA8BjFPaUYd0NuuAblK3JQ7MUEU371lINQRM+Z4QZowIZZbm0uJpHqQ4NcCsNn
LIP+miECgYEA957kkw4z/xdCQcfK5B3vSBf+VhIpNhH/vE18Z7i0kTOX0BedEMpX
3TUd1nzfbyymZAxk3Vis1Dj46NvE2+GDaiCzm7PPsZeSGE7LNtCi9930Q6pQsId5
+iWQhatRsg6zfQarhI6ul8YYcB3zwL51H8eRZDl1NXwy8oI5eyvEgw0CgYEA9Qyu
Oh44wcrXswazrJBmVGoC+kXenZJ8lVp1S5UnEZRDfhSXf8RUj+sARbCGRYedZqtd
2H+vaG5AyiRJcCjSYCAfyh/DYYFKzJ76D6xV6h5NpbJx6xUWEwfxgP84Of3YK6z1
zifU2eGhu5o8CJhU3eRA348x82zvxPXSU/inby8CgYBSDs/Eg9JrWHPWhLURv3HK
PFlGgKIzjudmqW7umGEONUC77vdX1xYi8jU/HQaWOv+w7AKI75fmhDLIR/wGucbo
5olescnEGmyJraLeOWmoJl+KBOjUdzDO2p/4C/v4u7JzXkB8nyPwm+8BSIu8deEu
dN4Tjo7u+IeRoeIWlTx8CQKBgBu7oKgxLWk5RKodMw5vlTUufkHG0IfywSjCAQ5Z
xf8mUXEecXrjRFK5XOGGNdv+miC5ejh7UuW1vJ1j9++6nvyEBjUA3ULWuBlqUJCf
h2WkolMDXAMn8sSanIll2P4vLVzcCUGYnm0+LOinbu3mF4y5PWJPuW58QLKAw5n/
RSu/AoGAH5miv08oDmLaxSBG0+7pukI3WK8AskxtFvhdvLH3zkHvYBXglBGfRVNe
x03TA4KebgVHxWU+ozn/jOFwXg1m8inSt3LolR9pARSHXCbwerhvE9fN+QA9CPqq
YHoJ5UwIFj2Ifw/YHKJAgxG3vxApbLqMJEiCg3WajkqUhjhXZU8=
-----END RSA PRIVATE KEY-----'''

    test_key_file = None
    test_data_file = None
    file_data = array("B", 5000 * [0])
    test_out_dir = None

    class Args:
        pass

    @classmethod
    def setUpClass(cls):
        cls.test_key_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_key_file.write(cls.private_key)
        cls.test_key_file.close()

        cls.test_data_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_data_file.write(cls.file_data)
        cls.test_data_file.close()

        cls.test_out_dir = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.test_key_file.name)
        os.unlink(cls.test_data_file.name)
        cls.test_out_dir.cleanup()

    def _create_args(self):
        args = ManifestWriterTest.Args()
        args.schema = 'Hashed'
        args.manifest_prefix = None
        args.data_prefix = None
        args.filename = self.test_data_file.name
        args.key_file = self.test_key_file.name
        args.key_pass = None
        args.max_size = 1500
        args.name = 'ccnx:/foo/bar'
        args.root_flag = False,
        args.tree_degree = 4
        args.out_dir = self.test_out_dir.name
        args.manifest_locator = 'ccnx:/foo.bar'
        args.data_locator = 'ccnx:/foo.bar'
        args.root_expiry = '2019-10-11T01:02:03+00:00'
        args.node_expiry = None
        args.data_expiry = '2019-10-11T01:02:03+00:00'
        args.enc_key = None
        args.key_num = None
        args.wrap_key = None
        args.wrap_pass = None
        return args

    def test_manifest(self):
        args = self._create_args()
        packet_writer = TreeIO.PacketMemoryWriter()
        mw = ManifestWriter(args=args, packet_writer=packet_writer)
        root_packet = mw.build()
        print(root_packet)

        buffer = TreeIO.DataBuffer()
        traversal = Traversal(packet_input=TreeIO.PacketMemoryReader(packet_writer), data_writer=buffer)
        traversal.preorder(root_packet)
        self.assertEqual(self.file_data, buffer.buffer)

        # There are 4 objects: 1 root, 1 leaf manifest, 1 long 0's data, 1 short 0's data
        # The long 0's content object is repeated 3 times, so we've achieved data deduplication
        self.assertEqual(4, buffer.count)

        # There were 6 packets created, but 3 of them were wall long strings of '0' and have the same hash
        self.assertEqual(4, len(packet_writer))

    def test_to_directory(self):
        args = self._create_args()

        mw = ManifestWriter(args=args,
                            packet_writer=TreeIO.PacketDirectoryWriter(directory=self.test_out_dir.name))
        root_packet = mw.build()
        print(root_packet)

        packet_reader = TreeIO.PacketDirectoryReader(self.test_out_dir.name)
        buffer = TreeIO.DataBuffer()
        traversal = Traversal(packet_input=packet_reader, data_writer=buffer)
        traversal.preorder(root_packet)
        self.assertEqual(self.file_data, buffer.buffer)

        # There are 4 objects: 1 root, 1 leaf manifest, 1 long 0's data, 1 short 0's data
        # The long 0's content object is repeated 3 times, so we've achieved data deduplication
        self.assertEqual(4, buffer.count)


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(ManifestWriterTest())
