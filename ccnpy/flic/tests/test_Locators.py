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


class test_Locators(unittest.TestCase):
    def test_serialize_nonfinal(self):
        loc1 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/a/b')))
        loc2 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/c')))
        locators = ccnpy.flic.Locators(final=False, locators=[loc1, loc2])
        actual = locators.serialize()
        expected = array.array("B", [0, 3, 0, 31,
                                     0, 2, 0, 14,
                                     0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                     0, 2, 0,  9,
                                     0, 0, 0,  5, 0, 1, 0, 1, 99
                                     ])
        self.assertEqual(expected, actual)

    def test_parse_nonfinal(self):
        loc1 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/a/b')))
        loc2 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/c')))
        expected = ccnpy.flic.Locators(final=False, locators=[loc1, loc2])
        wire_format = array.array("B", [0, 3, 0, 31,
                                        0, 2, 0, 14,
                                        0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                        0, 2, 0,  9,
                                        0, 0, 0,  5, 0, 1, 0, 1, 99
                                        ])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.flic.Locators.parse(tlv)
        self.assertEqual(expected, actual)

    def test_serialize_final(self):
        loc1 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/a/b')))
        loc2 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/c')))
        locators = ccnpy.flic.Locators(final=True, locators=[loc1, loc2])
        actual = locators.serialize()
        expected = array.array("B", [0, 3, 0, 35,
                                     0, 1, 0,  0,
                                     0, 2, 0, 14,
                                     0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                     0, 2, 0,  9,
                                     0, 0, 0,  5, 0, 1, 0, 1, 99
                                     ])
        self.assertEqual(expected, actual)

    def test_parse_final(self):
        loc1 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/a/b')))
        loc2 = ccnpy.flic.Locator(ccnpy.Link(name=ccnpy.Name.from_uri('ccnx:/c')))
        expected = ccnpy.flic.Locators(final=True, locators=[loc1, loc2])
        wire_format = array.array("B", [0, 3, 0, 35,
                                        0, 1, 0,  0,
                                        0, 2, 0, 14,
                                        0, 0, 0, 10, 0, 1, 0, 1, 97, 0, 1, 0, 1, 98,
                                        0, 2, 0,  9,
                                        0, 0, 0,  5, 0, 1, 0, 1, 99
                                        ])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.flic.Locators.parse(tlv)
        self.assertEqual(expected, actual)
