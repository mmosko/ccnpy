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

from ccnpy.core.Link import Link
from ccnpy.core.Name import Name
from ccnpy.core.Tlv import Tlv
from ccnpy.flic.tlvs.Locator import Locator
from ccnpy.flic.tlvs.Locators import Locators
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class LocatorsTest(CcnpyTestCase):
    wire_format = array.array("B", [
                                    0, TlvNumbers.T_LOCATORS, 0, 31,
                                    0, TlvNumbers.T_LINK, 0, 14,
                                    0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                    0, TlvNumbers.T_LINK, 0, 9,
                                    0, 0, 0, 5, 0, 1, 0, 1, 99
                                    ])

    def test_serialize_final(self):
        loc1 = Locator.from_uri('ccnx:/a/b')
        loc2 = Locator.from_uri('ccnx:/c')
        locators = Locators(locators=[loc1, loc2])
        actual = locators.serialize()
        self.assertEqual(self.wire_format, actual)

    def test_parse_final(self):
        loc1 = Locator(Link(name=Name.from_uri('ccnx:/a/b')))
        loc2 = Locator(Link(name=Name.from_uri('ccnx:/c')))
        expected = Locators(locators=[loc1, loc2])

        tlv = Tlv.deserialize(self.wire_format)
        actual = Locators.parse(tlv)
        self.assertEqual(expected, actual)
