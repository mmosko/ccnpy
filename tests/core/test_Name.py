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

import ccnpy


class Name_Test(unittest.TestCase):
    def test_from_uri(self):
        uri='ccnx:/apple/banana/cherry/durian'
        name = ccnpy.Name.from_uri(uri)
        wire_format = name.serialize()
        truth = array.array('B', [0, 0, 0, 39,
                                  0, 1, 0, 5, 97, 112, 112, 108, 101,
                                  0, 1, 0, 6, 98, 97, 110, 97, 110, 97,
                                  0, 1, 0, 6, 99, 104, 101, 114, 114, 121,
                                  0, 1, 0, 6, 100, 117, 114, 105, 97, 110])

        self.assertEqual(wire_format, truth, 'incorrect wire format')

    def test_components(self):
        uri='ccnx:/apple/banana/cherry/durian'
        name = ccnpy.Name.from_uri(uri)
        self.assertEqual(name.count(), 4)
        self.assertEqual(name[0], 'apple')
        self.assertEqual(name[1], 'banana')
        self.assertEqual(name[2], 'cherry')
        self.assertEqual(name[3], 'durian')

    def test_deserialize(self):
        wire_format = array.array('B', [0, 0, 0, 39,
                                        0, 1, 0, 5, 97, 112, 112, 108, 101,
                                        0, 1, 0, 6, 98, 97, 110, 97, 110, 97,
                                        0, 1, 0, 6, 99, 104, 101, 114, 114, 121,
                                        0, 1, 0, 6, 100, 117, 114, 105, 97, 110])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.Name.parse(tlv)
        expected = ccnpy.Name.from_uri('ccnx:/apple/banana/cherry/durian')
        self.assertEqual(expected, actual, "Incorrect deserialize")
