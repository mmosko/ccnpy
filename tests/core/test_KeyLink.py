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
from ccnpy.core.KeyLink import KeyLink
from ccnpy.core.Link import Link
from ccnpy.core.Name import Name
from ccnpy.core.Tlv import Tlv


class KeyLinkTest(CcnpyTestCase):
    def test_serialize(self):
        name = Name.from_uri('ccnx:/a/b')
        keyid = HashValue(1, b'ab')
        digest = HashValue(2, b'ABCD')
        link = KeyLink(Link(name=name, keyid=keyid, digest=digest))
        actual = link.serialize()
        expected = array.array("B", [
            0, 14, 0, 36,
            0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
            0, 2, 0, 6, 0, 1, 0, 2, 97, 98,
            0, 3, 0, 8, 0, 2, 0, 4, 65, 66, 67, 68])
        self.assertEqual(expected, actual)

        decoded = KeyLink.parse(Tlv.deserialize(actual))
        self.assertEqual(link, decoded)
