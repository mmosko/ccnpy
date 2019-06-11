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
from datetime import datetime

import ccnpy


class ContentObject_Test(unittest.TestCase):
    def test_serialize(self):
        name = ccnpy.Name.from_uri('ccnx:/apple/pie')
        payload = ccnpy.Payload(array.array("B", [1, 3, 5, 7, 9]))
        dt = datetime.utcfromtimestamp(1560227545.906)
        co = ccnpy.ContentObject.create_data(name=name, payload=payload, expiry_time=dt)
        name_tlv = co.name()
        payload_type_tlv = co.payload_type()
        payload_tlv = co.payload()
        expiry_tlv = co.expiry_time()
        byte_list= name_tlv.serialize()
        byte_list.extend(expiry_tlv.serialize())
        byte_list.extend(payload_type_tlv.serialize())
        byte_list.extend(payload.serialize())
        length = len(byte_list)
        expected = array.array("B", [0, 2, 0, length])
        expected.extend(byte_list)
        actual = co.serialize()
        self.assertEqual(expected, actual, "Incorrect serialization")

    def test_deserialize(self):
        wire_format = array.array('B', [0, 2, 0, 46,
                                        0, 0, 0, 16, 0, 1, 0, 5, 97, 112, 112, 108, 101, 0, 1, 0, 3, 112, 105, 101,
                                        0, 6, 0, 8, 0, 0, 1, 107, 70, 79, 136, 178,
                                        0, 5, 0, 1, 0,
                                        0, 1, 0, 5, 1, 3, 5, 7, 9])
        tlv = ccnpy.Tlv.deserialize(wire_format)
        actual = ccnpy.ContentObject.deserialize(tlv)

        name = ccnpy.Name.from_uri('ccnx:/apple/pie')
        payload = ccnpy.Payload(array.array("B", [1, 3, 5, 7, 9]))
        dt = datetime.utcfromtimestamp(1560227545.906)
        expected = ccnpy.ContentObject.create_data(name=name, payload=payload, expiry_time=dt)
        self.assertEqual(expected, actual, "Incorrect deserialization")

