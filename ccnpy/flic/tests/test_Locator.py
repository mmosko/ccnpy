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

import unittest
import array
import ccnpy
import ccnpy.flic


class test_Locator(unittest.TestCase):
    def test_serialize(self):
        name=ccnpy.Name.from_uri('ccnx:/a/b')
        keyid=ccnpy.HashValue(1, array.array("B", b'ab'))
        digest=ccnpy.HashValue(2, array.array("B", b'ABCD'))
        link = ccnpy.Link(name=name, keyid=keyid, digest=digest)
        locator = ccnpy.flic.Locator(link)
        actual = locator.serialize()
        expected = array.array("B", [0, 2, 0, 36,
                                     0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                     0, 2, 0, 6, 0, 1, 0, 2, 97, 98,
                                     0, 3, 0, 8, 0, 2, 0, 4, 65, 66, 67, 68])
        self.assertEqual(expected, actual)

    def test_parse(self):
        wire_format = array.array("B", [0, 2, 0, 36,
                                        0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                        0, 2, 0, 6, 0, 1, 0, 2, 97, 98,
                                        0, 3, 0, 8, 0, 2, 0, 4, 65, 66, 67, 68])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        locator = ccnpy.flic.Locator.parse(tlv)

        name=ccnpy.Name.from_uri('ccnx:/a/b')
        keyid=ccnpy.HashValue(1, array.array("B", b'ab'))
        digest=ccnpy.HashValue(2, array.array("B", b'ABCD'))
        link = ccnpy.Link(name=name, keyid=keyid, digest=digest)
        expected = ccnpy.flic.Locator(link)
        self.assertEqual(expected, locator)
