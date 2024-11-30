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
from ccnpy.flic.tlvs.Locator import Locator
from ccnpy.flic.tlvs.TlvNumbers import TlvNumbers


class LocatorTest(CcnpyTestCase):
    def test_serialize(self):
        name=Name.from_uri('ccnx:/a/b')
        keyid=HashValue(1, array.array("B", b'ab'))
        digest=HashValue(2, array.array("B", b'ABCD'))
        link = Link(name=name, keyid=keyid, digest=digest)
        locator = Locator(link)
        actual = locator.serialize()
        expected = array.array("B", [
                                     0, TlvNumbers.T_LINK, 0, 36,
                                     0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                     0, 2, 0, 6, 0, 1, 0, 2, 97, 98,
                                     0, 3, 0, 8, 0, 2, 0, 4, 65, 66, 67, 68])
        self.assertEqual(expected, actual)

    def test_parse(self):
        wire_format = array.array("B", [
                                        0, TlvNumbers.T_LINK, 0, 36,
                                        0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                        0, 2, 0, 6, 0, 1, 0, 2, 97, 98,
                                        0, 3, 0, 8, 0, 2, 0, 4, 65, 66, 67, 68])
        tlv = Tlv.deserialize(wire_format)
        locator = Locator.parse(tlv)

        name=Name.from_uri('ccnx:/a/b')
        keyid=HashValue(1, array.array("B", b'ab'))
        digest=HashValue(2, array.array("B", b'ABCD'))
        link = Link(name=name, keyid=keyid, digest=digest)
        expected = Locator(link)
        self.assertEqual(expected, locator)
