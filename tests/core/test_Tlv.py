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


class TlvTest(unittest.TestCase):
    def test_serialize_array(self):
        type = 0x1234
        value = array.array("B", [10, 11, 12, 13])
        tlv = Tlv(tlv_type=type, value=value)
        #print(tlv)

        wire_format = tlv.serialize()
        truth = array.array("B", [0x12, 0x34, 0x00, 0x04])
        truth.extend(value)

        self.assertEqual(truth, wire_format, "wire format incorrect")

    def test_serialize_tlv(self):
        inner_tlv = Tlv(tlv_type=0x0001, value=[10, 11, 12, 13])
        outer_tlv = Tlv(tlv_type=0x0002, value=inner_tlv)
        wire_format = outer_tlv.serialize()

        truth = array.array("B", [0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13])
        self.assertEqual(truth, wire_format, "wire format incorrect")

    def test_equal(self):
        a = Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        b = Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        c = Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        self.assertEqual(a, b)
        self.assertEqual(b, c)
        self.assertEqual(c, a)

    def test_deserialize(self):
        wire_format = array.array("B", [0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13])
        truth = Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        actual = Tlv.deserialize(wire_format)
        self.assertEqual(truth, actual)

    def test_tlv_array_value(self):
        a = Tlv(tlv_type=1, value=array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        b = Tlv(tlv_type=2, value=array.array("B", [10, 11, 12, 13]))
        c = None
        d = Tlv(tlv_type=4, value=array.array("B", [10, 11, 12, 13]))

        tlv = Tlv(1, [a, b, c, d])
        expected = array.array("B", [0, 1, 0, 28,
                                     0, 1, 0, 8, 0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13,
                                     0, 2, 0, 4, 10, 11, 12, 13,
                                     0, 4, 0, 4, 10, 11, 12, 13])
        actual = tlv.serialize()
        self.assertEqual(expected, actual)

    def test_extend(self):
        a = Tlv(1, array.array("B", [2, 3, 4]))
        b = Tlv(5, array.array("B", [6, 7]))
        c = a.extend(b)
        actual = c.serialize()

        expected = array.array("B", [0, 1, 0, 9,
                                     2, 3, 4,
                                     0, 5, 0, 2, 6, 7])
        self.assertEqual(expected, actual)

