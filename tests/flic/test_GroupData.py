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

import ccnpy
import ccnpy.flic


class test_GroupData(unittest.TestCase):
    def test_serialize(self):
        size = ccnpy.flic.SubtreeSize(0x0102)
        digest = ccnpy.HashValue.create_sha256(array.array("B", [100, 110, 120]))
        loc1 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/a/b')))
        loc2 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/c')))
        locators = ccnpy.flic.LocatorList(final=True, locators=[loc1, loc2])

        gd = ccnpy.flic.GroupData(subtree_size=size, subtree_digest=digest, locators=locators)
        actual = gd.serialize()

        expected = array.array("B", [0, 1, 0, 62,
                                     0, 1, 0,  8, 0, 0, 0, 0,   0,   0,   1,   2,
                                     0, 2, 0,  7, 0, 1, 0, 3, 100, 110, 120,
                                     # LocatorList
                                     0, 3, 0, 35,
                                     0, 1, 0, 0,
                                     0, 2, 0, 14,
                                     0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                     0, 2, 0, 9,
                                     0, 0, 0, 5, 0, 1, 0, 1, 99
                                     ])
        self.assertEqual(expected, actual)

    def test_parse(self):
        size = ccnpy.flic.SubtreeSize(0x0102)
        digest = ccnpy.HashValue.create_sha256(array.array("B", [100, 110, 120]))
        loc1 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/a/b')))
        loc2 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/c')))
        locators = ccnpy.flic.LocatorList(final=True, locators=[loc1, loc2])

        expected = ccnpy.flic.GroupData(subtree_size=size, subtree_digest=digest, locators=locators)

        wire_format = array.array("B", [0, 1, 0, 62,
                                        0, 1, 0,  8, 0, 0, 0, 0,   0,   0,   1,   2,
                                        0, 2, 0,  7, 0, 1, 0, 3, 100, 110, 120,
                                        # LocatorList
                                        0, 3, 0, 35,
                                        0, 1, 0, 0,
                                        0, 2, 0, 14,
                                        0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                        0, 2, 0, 9,
                                        0, 0, 0, 5, 0, 1, 0, 1, 99
                                        ])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.flic.GroupData.parse(tlv)

        self.assertEqual(expected, actual)
