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


import array
from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Link import Link
from ccnpy.core.Name import Name
from ccnpy.core.Tlv import Tlv
from ccnpy.flic.ManifestTreeOptions import ManifestTreeOptions
from ccnpy.flic.name_constructor.HashSchemaImpl import HashSchemaImpl
from ccnpy.flic.name_constructor.NameConstructorContext import NameConstructorContext
from ccnpy.flic.name_constructor.SchemaImplFactory import SchemaImplFactory
from ccnpy.flic.name_constructor.SchemaType import SchemaType
from ccnpy.flic.tlvs.Locator import Locator
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import HashSchema
from ccnpy.flic.tlvs.NodeData import NodeData
from ccnpy.flic.tlvs.SubtreeDigest import SubtreeDigest
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class NodeDataTest(CcnpyTestCase):
    def setUp(self):
        SchemaImplFactory.reset_nc_id()

    @staticmethod
    def _create_array():
        return array.array("B", [
                                     0, TlvNumbers.T_NODE_DATA, 0, 52,
                                     0, TlvNumbers.T_SUBTREE_SIZE, 0,  2, 1,   2,
                                     0, TlvNumbers.T_SUBTREE_DIGEST, 0,  7, 0, 1, 0, 3, 100, 110, 120,
                                     # LocatorList
                                     0, TlvNumbers.T_LOCATORS, 0, 31,
                                     0, TlvNumbers.T_LINK, 0, 14,
                                     0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                     0, TlvNumbers.T_LINK, 0, 9,
                                     0, 0, 0, 5, 0, 1, 0, 1, 99
                                     ])

    def test_serialize(self):
        size = SubtreeSize(0x0102)
        digest = SubtreeDigest(HashValue.create_sha256(array.array("B", [100, 110, 120])))
        loc1 = Locator(Link(name=Name.from_uri('ccnx:/a/b')))
        loc2 = Locator(Link(name=Name.from_uri('ccnx:/c')))
        locators = Locators(locators=[loc1, loc2])

        nd = NodeData(subtree_size=size, subtree_digest=digest, locators=locators)
        actual = nd.serialize()

        expected = self._create_array()
        self.assertEqual(expected, actual)

    def test_parse(self):
        size = SubtreeSize(0x0102)
        digest = SubtreeDigest(HashValue.create_sha256(array.array("B", [100, 110, 120])))
        loc1 = Locator(Link(name=Name.from_uri('ccnx:/a/b')))
        loc2 = Locator(Link(name=Name.from_uri('ccnx:/c')))
        locators = Locators(locators=[loc1, loc2])

        expected = NodeData(subtree_size=size, subtree_digest=digest, locators=locators)
        wire_format = self._create_array()
        tlv = Tlv.deserialize(wire_format)
        actual = NodeData.parse(tlv)

        self.assertEqual(expected, actual)

    def test_with_nc_defs_hashed(self):
        options=ManifestTreeOptions(
            name=Name.from_uri('ccnx:/root'),
            schema_type=SchemaType.HASHED,
            manifest_locators=Locators.from_uri('ccnx:/manifest'),
            data_locators=Locators.from_uri('ccnx:/data'),
            signer=None
        )
        name_ctx = NameConstructorContext.create(options)

        node_data = NodeData(subtree_size=SubtreeSize(0x1234), nc_defs=[name_ctx.manifest_schema_impl.nc_def(),
                                                                        name_ctx.data_schema_impl.nc_def()])

        wire_format = node_data.serialize()
        print(wire_format)

        expected_wire_format = array.array('B',
                                     [
                                        0, TlvNumbers.T_NODE_DATA, 0, 76,
                                        0, TlvNumbers.T_SUBTREE_SIZE, 0, 2, 18, 52,
                                        # NC DEF for NcId #1
                                        0, TlvNumbers.T_NCDEF, 0, 33,
                                            # ncid
                                            0, TlvNumbers.T_NCID, 0, 1, 1,
                                            # Hash Schema
                                            0, TlvNumbers.T_HashSchema, 0, 24,
                                                # locators
                                                0, TlvNumbers.T_LOCATORS, 0, 20,
                                                    # Locator
                                                    0, TlvNumbers.T_LINK, 0, 16,
                                                        # name
                                                        0, 0, 0, 12,
                                                            0, 1, 0, 8, 109, 97, 110, 105, 102, 101, 115, 116,
                                        # NC DEF for NcId #2
                                        0, TlvNumbers.T_NCDEF, 0, 29,
                                            # ncid
                                            0, TlvNumbers.T_NCID, 0, 1, 2,
                                            # Hash Schema
                                            0, TlvNumbers.T_HashSchema, 0, 20,
                                                # Locators
                                                0, TlvNumbers.T_LOCATORS, 0, 16,
                                                    # Locator
                                                    0, TlvNumbers.T_LINK, 0, 12,
                                                        0, 0, 0, 8, 0, 1, 0, 4, 100, 97, 116, 97])

        self.assertEqual(expected_wire_format, wire_format)
        decoded = Tlv.deserialize(wire_format)
        actual = NodeData.parse(decoded)
        self.assertEqual(node_data, actual)
