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
import unittest

from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.NcDef import NcDef
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.flic.tlvs.NcSchema import InterestDerivedSchema


class NcDefTest(unittest.TestCase):
    def test_serialize(self):
        nc_def = NcDef(nc_id=NcId(5), schema=InterestDerivedSchema())
        expected = array.array("B", [0, 6, 0, 9, 0, 16, 0, 1, 5, 0, 1, 0, 0])
        actual = nc_def.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        wire_format = array.array("B", [0, 6, 0, 9, 0, 16, 0, 1, 5, 0, 1, 0, 0])
        tlv = Tlv.deserialize(wire_format)
        actual = NcDef.parse(tlv)
        expected = NcDef(nc_id=NcId(5), schema=InterestDerivedSchema())
        self.assertEqual(expected, actual)

