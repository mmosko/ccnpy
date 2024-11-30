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

from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.Locator import Locator
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.NcDef import NcDef
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import HashSchema
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class NcDefTest(CcnpyTestCase):
    wire_format = array.array("B", [
        0, TlvNumbers.T_NCDEF, 0, 26,
        0, TlvNumbers.T_NCID, 0, 1, 5,
        0, TlvNumbers.T_HashSchema, 0, 17,
        0, TlvNumbers.T_LOCATORS, 0, 13,
        0, TlvNumbers.T_LINK, 0, 9,
        0, 0, 0, 5, 0, 1, 0, 1, 97])

    def test_serialize(self):
        nc_def = NcDef(nc_id=NcId(5), schema=HashSchema(locators=Locators.from_uri('ccnx:/a')))
        actual = nc_def.serialize()
        self.assertEqual(self.wire_format, actual)

    def test_deserialize(self):
        tlv = Tlv.deserialize(self.wire_format)
        actual = NcDef.parse(tlv)
        expected = NcDef(nc_id=NcId(5), schema=HashSchema(locators=Locators.from_uri('ccnx:/a')))
        self.assertEqual(expected, actual)

