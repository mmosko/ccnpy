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

import io
import unittest
from array import array

import ccnpy
import ccnpy.flic
from ccnpy.crypto import RsaKey, RsaSha256_Signer
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.tree import Traversal
from ccnpy.flic.tree import TreeIO


class test_ManifestTree(unittest.TestCase):

    # openssl genrsa -out test_key.pem
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

    # openssl rsa -in test_key.pem -pubout -out rsa_pub.pem
    public_key = b'''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QdUuaoTr4gA1bMoCdjU
NPqpb7f211TYFcahHhaBPnBwQwYjNIV1HUmKnJiLn59F36iZFYgNR53O30F7g0/o
R2MWVaJoeSKq7UP7gqlSjrplZEaIYx1MvFKjWAHRDsVTdPNGKqNt8wFZgzxTZw24
IlBIk0hOXlgV70TIbo9TvZ9Wl7nIUihz66OmY1b+DEokjphEjzX1PJK/a/Xat4L0
CRnUVSZ+VGbaqbzkT1FKHTfCVSk6Jcz7/EtcKnKyajCVcQKoL8Zgv4oXqWzXcGJK
ewM/87c2S2qMwdocG0XZx90GqEI9Jk+Rs6JKJoYf9GTW6yDBAH+wGISSPQj0U2Gy
YwIDAQAB
-----END PUBLIC KEY-----'''


    def test_nary_1_2_14(self):
        """
        3-way tree with 1 direct and 2 indirect and 14 file chunks

        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()

        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = io.BytesIO(self.private_key)

        root_name = ccnpy.Name.from_uri("ccnx:/example.com/manifest")

        rsa_key = RsaKey(pem_key=self.private_key)
        root_signer = RsaSha256_Signer(key=rsa_key)

        tree = ccnpy.flic.ManifestTree(data_input=data_input,
                                       packet_output=packet_buffer,
                                       root_manifest_name=root_name,
                                       root_manifest_signer=root_signer,
                                       max_packet_size = 145,
                                       tree_options = ManifestTreeOptions(debug=False))

        root_manifest = tree.build()

        expected = array("B", self.private_key)
        actual_data = TreeIO.DataBuffer()
        traversal = Traversal(packet_input=packet_buffer, data_buffer=actual_data, decryptor=None)
        traversal.preorder(root_manifest)

        # We have 1674 bytes.  We can fit 124 bytes in a data content object, so we need 14 data object.
        # With 3 pointers per node, we need 4 leaf manifests and 3 interior manifests.

        self.assertEqual(expected, actual_data.buffer)
        self.assertEqual(14, actual_data.count)
        # 14 data nodes plus 4 leaf manifests plus 3 interior manifests plus 1 root manifest
        self.assertEqual(22, len(packet_buffer))

    def test_max_tree_degree(self):
        """
        Use a large packet size, but limit the tree degree to 3.
        :return:
        """
        packet_buffer = TreeIO.PacketMemoryWriter()

        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = io.BytesIO(self.private_key)

        root_name = ccnpy.Name.from_uri("ccnx:/example.com/manifest")

        rsa_key = RsaKey(pem_key=self.private_key)
        root_signer = RsaSha256_Signer(key=rsa_key)

        tree = ccnpy.flic.ManifestTree(data_input=data_input,
                                       packet_output=packet_buffer,
                                       root_manifest_name=root_name,
                                       root_manifest_signer=root_signer,
                                       max_packet_size = 400,
                                       tree_options = ManifestTreeOptions(max_tree_degree=3, debug=False))

        root_manifest = tree.build()

        expected = array("B", self.private_key)
        actual_data = TreeIO.DataBuffer()
        traversal = Traversal(packet_input=packet_buffer, data_buffer=actual_data, decryptor=None)
        traversal.preorder(root_manifest)

        # We have 1674 bytes.  5 data objects plus 1 leaf manifests and 1 interior manifest

        self.assertEqual(expected, actual_data.buffer)
        self.assertEqual(5, actual_data.count)
        # 5 data nodes plus 1 leaf manifests plus 1 interior manifests plus 1 root manifest
        self.assertEqual(8, len(packet_buffer))
