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
from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.GroupData import GroupData
from ccnpy.flic.tlvs.LeafDigest import LeafDigest
from ccnpy.flic.tlvs.LeafSize import LeafSize
from ccnpy.flic.tlvs.StartSegmentId import StartSegmentId
from ccnpy.flic.tlvs.SubtreeDigest import SubtreeDigest
from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class GroupDataTest(CcnpyTestCase):
    wire_format = array.array("B", [
                                    0, TlvNumbers.T_GROUP_DATA, 0, 17,
                                    0, TlvNumbers.T_SUBTREE_SIZE, 0, 2, 1, 2,
                                    0, TlvNumbers.T_SUBTREE_DIGEST, 0, 7, 0, 1, 0, 3, 100, 110, 120,
                                    ])

    def test_serialize(self):
        size = SubtreeSize(0x0102)
        digest = SubtreeDigest(HashValue.create_sha256(array.array("B", [100, 110, 120])))

        gd = GroupData(subtree_size=size, subtree_digest=digest)
        actual = gd.serialize()
        self.assertEqual(self.wire_format, actual)

    def test_parse(self):
        size = SubtreeSize(0x0102)
        digest = SubtreeDigest(HashValue.create_sha256(array.array("B", [100, 110, 120])))
        expected = GroupData(subtree_size=size, subtree_digest=digest)
        tlv = Tlv.deserialize(self.wire_format)
        actual = GroupData.parse(tlv)

        self.assertEqual(expected, actual)

    def test_leaf_size(self):
        gd = GroupData(leaf_size = LeafSize(0x1234))
        wire_format = gd.serialize()
        expected_wire = array.array("B", [
            0, TlvNumbers.T_GROUP_DATA, 0, 6,
            0, TlvNumbers.T_LEAF_SIZE, 0, 2, 0x12, 0x34])
        self.assertEqual(expected_wire, wire_format)
        decoded = GroupData.parse(Tlv.deserialize(wire_format))
        self.assertEqual(gd, decoded)

    def test_leaf_digest(self):
        gd = GroupData(leaf_digest = LeafDigest(HashValue.create_sha256(array.array("B", [100, 110, 120]))))
        wire_format = gd.serialize()
        expected_wire = array.array("B", [
            0, TlvNumbers.T_GROUP_DATA, 0, 11,
            0, TlvNumbers.T_LEAF_DIGEST, 0, 7, 0, 1, 0, 3, 100, 110, 120])
        self.assertEqual(expected_wire, wire_format)
        decoded = GroupData.parse(Tlv.deserialize(wire_format))
        self.assertEqual(gd, decoded)

    def test_nc_id(self):
        gd = GroupData(nc_id = NcId(9))
        wire_format = gd.serialize()
        expected_wire = array.array("B", [
            0, TlvNumbers.T_GROUP_DATA, 0, 5,
            0, TlvNumbers.T_NCID, 0, 1, 9])
        self.assertEqual(expected_wire, wire_format)
        decoded = GroupData.parse(Tlv.deserialize(wire_format))
        self.assertEqual(gd, decoded)

    def test_start_segment_id(self):
        gd = GroupData(start_segment_id = StartSegmentId(9))
        wire_format = gd.serialize()
        expected_wire = array.array("B", [
            0, TlvNumbers.T_GROUP_DATA, 0, 5,
            0, TlvNumbers.T_START_SEGMENT_ID, 0, 1, 9])
        self.assertEqual(expected_wire, wire_format)
        decoded = GroupData.parse(Tlv.deserialize(wire_format))
        self.assertEqual(gd, decoded)