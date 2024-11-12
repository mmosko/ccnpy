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


import io
import unittest
from array import array
from binascii import unhexlify

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Name import Name
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256Signer
from ccnpy.flic.ManifestTree import ManifestTree
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.SchemaImplFactory import SchemaImplFactory
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.HashGroup import HashGroup
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.NcDef import NcDef
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import SegmentedSchema
from ccnpy.flic.tlvs.Node import Node
from ccnpy.flic.tlvs.NodeData import NodeData
from ccnpy.flic.tlvs.Pointers import Pointers
from ccnpy.flic.tlvs.StartSegmentId import StartSegmentId
from ccnpy.flic.tree.Traversal import Traversal
from ccnpy.flic.tree.TreeIO import TreeIO
from tests.MockReader import MockReader


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

    def setUp(self):
        SchemaImplFactory.reset_nc_id()
        self.packet_buffer = TreeIO.PacketMemoryWriter()
        self.rsa_key = RsaKey(pem_key=self.private_key)
        self.root_signer = RsaSha256Signer(key=self.rsa_key)

    def _create_options(self, max_packet_size, schema_type=SchemaType.HASHED):
        if schema_type == SchemaType.HASHED:
            return ManifestTreeOptions(name=Name.from_uri("ccnx:/example.com/manifest"),
                                          schema_type=schema_type,
                                          manifest_locators=Locators.from_uri('ccnx:/x/y'),
                                          signer=self.root_signer,
                                          max_packet_size=max_packet_size,
                                          max_tree_degree=3,
                                          debug=True)
        else:
            return ManifestTreeOptions(name=Name.from_uri("ccnx:/example.com/manifest"),
                                          schema_type=schema_type,
                                          manifest_prefix=Name.from_uri('ccnx:/manifest'),
                                          data_prefix=Name.from_uri('ccnx:/data'),
                                          signer=self.root_signer,
                                          max_packet_size=max_packet_size,
                                          max_tree_degree=3,
                                          debug=True)

    def test_nary_1_2_14(self):
        """
        3-way tree with 2 direct and 1 indirect per node.

        :return:
        """
        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = io.BytesIO(self.private_key)

        tree = ManifestTree(data_input=data_input,
                            packet_output=self.packet_buffer,
                            tree_options=self._create_options(250))

        root_manifest = tree.build()

        expected = array("B", self.private_key)
        actual_data = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=actual_data, packet_input=self.packet_buffer, build_graph=False)
        traversal.preorder(root_manifest, nc_cache=Traversal.NameConstructorCache(copy=tree.name_context().export_schemas()))
        # traversal.get_graph().save('tree.dot')

        self.assertEqual(expected, actual_data.buffer)
        self.assertEqual(8, actual_data.count)

        # 13 = 8 data objects + 1 top + 3 interior + 1 leaf
        self.assertEqual(13, len(self.packet_buffer))

    def test_max_tree_degree(self):
        """
        Use a large packet size, but limit the tree degree to 3.
        :return:
        """
        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = io.BytesIO(self.private_key)

        tree = ManifestTree(data_input=data_input,
                            packet_output=self.packet_buffer,
                            tree_options=self._create_options(400))

        root_manifest = tree.build()

        expected = array("B", self.private_key)
        actual_data = TreeIO.DataBuffer()

        traversal = Traversal(data_writer=actual_data, packet_input=self.packet_buffer)
        traversal.preorder(root_manifest, nc_cache=Traversal.NameConstructorCache(copy=tree.name_context().export_schemas()))
        # We have 1674 bytes.  5 data objects plus 1 leaf manifests and 1 interior manifest

        self.assertEqual(expected, actual_data.buffer)
        self.assertEqual(5, actual_data.count)
        # 5 data nodes plus 1 leaf manifests plus 1 interior manifests plus 1 root manifest
        self.assertEqual(8, len(self.packet_buffer))

    def _test_root_manifest(self, actual_root_manifest_packet):
        expected_root_manifest = Manifest(
            node=Node(
                node_data=NodeData(nc_defs=[
                    NcDef(NcId(1), SegmentedSchema.create_for_manifest(Name.from_uri('ccnx:/manifest'))),
                    NcDef(NcId(2), SegmentedSchema.create_for_data(Name.from_uri('ccnx:/data'))),
                ]),
                hash_groups=[
                    HashGroup(
                        group_data=GroupData(nc_id=NcId(1), start_segment_id=StartSegmentId(0)),
                        pointers=Pointers([HashValue.create_sha256(unhexlify('445eaea33112ddf0d21cf3762cb49c29c28c97ab9da3917356f16884136614c1'))]))
                ]
            )
        )
        actual_root_manifest = Manifest.from_content_object(actual_root_manifest_packet.body())
        self.assertEqual(expected_root_manifest, actual_root_manifest)
        self.assertEqual(actual_root_manifest_packet.body().name(), Name.from_uri("ccnx:/example.com/manifest"))

    def _test_top_manifest(self, actual_top_manifest_packet):
        manifest_prefix = Name.from_uri('ccnx:/manifest')
        expected_top_manifest = Manifest(
            node=Node(
                hash_groups=[
                    HashGroup(
                        group_data=GroupData(nc_id=NcId(2), start_segment_id=StartSegmentId(0)),
                        pointers=Pointers([
                            HashValue.create_sha256(
                                unhexlify('eb96aebb6f998228f6d7060f50385d6378121522b9e13cfe98e1a39ebff3f4cc')),
                        ])),
                    HashGroup(
                        group_data=GroupData(nc_id=NcId(1), start_segment_id=StartSegmentId(1)),
                        pointers=Pointers([
                            HashValue.create_sha256(
                                unhexlify('64a6960798d558159cd666820cf2b0081506fd3f589447ce68a54cb92e9a92b8')),
                            HashValue.create_sha256(
                                unhexlify('de4301ebb864bf1f9ebada9fc47da014dc44f9f3f8d118ce685323c9b91a7cc7')),
                        ])),
                ]
            )
        )
        expected_top_packet = expected_top_manifest.packet(name=manifest_prefix.append_manifest_id(0))
        print(expected_top_packet)
        self.assertEqual(expected_top_packet, actual_top_manifest_packet)

    def test_segmented_tree(self):
        """
        Use a large packet size, but limit the tree degree to 3.

        solution={OptResult n=23, p=3, dir=1, ind=2, int=5, leaf=6, w=0, h=4}

                     top
                A           B
             C            u   v
          G   H
         z x y w

        :return:
        """
        # setup a source to use as a byte array.  Use the private key, as we already have that as a bytearray.
        data_input = MockReader(data=array("B", [x % 256 for x in range(0, 8000)]))

        tree = ManifestTree(data_input=data_input,
                            packet_output=self.packet_buffer,
                            tree_options=self._create_options(400, SchemaType.SEGMENTED))

        root_manifest_packet = tree.build()

        expected = data_input.data
        actual_data = TreeIO.DataBuffer()
        traversal = Traversal(data_writer=actual_data, packet_input=self.packet_buffer, debug=False, build_graph=True)
        traversal.preorder(root_manifest_packet, nc_cache=Traversal.NameConstructorCache(copy=tree.name_context().export_schemas()))
        traversal.get_graph().plot()

        self.assertEqual(expected, actual_data.buffer)

        # We have 8000 bytes of data.
        # We get 353 bytes of data per data object, so there's 23 data objects.
        # We get 3 pointers per manifest, so we need leaf 8 manifests, plus the root, plus 3 internal
        # root -> top -> {m1, m2, m3} -> {leaf1, ..., leaf8}
        self.assertEqual(23, actual_data.count)

        # 23 data + root + top + 3 internal + 8 leaf = 36
        self.assertEqual(36, len(self.packet_buffer))

        self._test_root_manifest(root_manifest_packet)
        self._test_top_manifest(self.packet_buffer.packets[-2])
