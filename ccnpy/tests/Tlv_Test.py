# Copyright 2019 Marc Mosko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
import array
import ccnpy


class Tlv_Test(unittest.TestCase):
    def test_serialize_array(self):
        type = 0x1234
        value = array.array("B", [10, 11, 12, 13])
        tlv = ccnpy.Tlv(type=type, value=value)
        #print(tlv)

        wire_format = tlv.serialize()
        truth = array.array("B", [0x12, 0x34, 0x00, 0x04])
        truth.extend(value)

        #print("truth  = %r" % truth)
        #print("actual = %r" % wire_format)
        self.assertEqual(truth, wire_format, "wire format incorrect")

    def test_serialize_tlv(self):
        inner_tlv = ccnpy.Tlv(type=0x0001, value=[10, 11, 12, 13])
        outer_tlv = ccnpy.Tlv(type=0x0002, value=inner_tlv)
        wire_format = outer_tlv.serialize()

        truth = array.array("B", [0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13])
        print("truth  = %r" % truth)
        print("actual = %r" % wire_format)
        self.assertEqual(truth, wire_format, "wire format incorrect")

    def test_equal(self):
        a = ccnpy.Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        b = ccnpy.Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        c = ccnpy.Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        self.assertEqual(a, b)
        self.assertEqual(b, c)
        self.assertEqual(c, a)

    def test_deserialize(self):
        wire_format = array.array("B", [0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13])
        truth = ccnpy.Tlv(2, array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        actual = ccnpy.Tlv.deserialize(wire_format)
        self.assertEqual(truth, actual)

    def test_tlv_array_value(self):
        a = ccnpy.Tlv(type=1, value=array.array("B", [0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13]))
        b = ccnpy.Tlv(type=2, value=array.array("B", [10, 11, 12, 13]))
        c = None
        d = ccnpy.Tlv(type=4, value=array.array("B", [10, 11, 12, 13]))

        tlv = ccnpy.Tlv(1, [a, b, c, d])
        expected = array.array("B", [0, 1, 0, 28,
                                     0, 1, 0, 8, 0x00, 0x01, 0x00, 0x04, 10, 11, 12, 13,
                                     0, 2, 0, 4, 10, 11, 12, 13,
                                     0, 4, 0, 4, 10, 11, 12, 13])
        actual = tlv.serialize()
        self.assertEqual(expected, actual)