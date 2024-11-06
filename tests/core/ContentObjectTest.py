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
from datetime import datetime, UTC

from ccnpy.core.ContentObject import ContentObject
from ccnpy.core.Name import Name
from ccnpy.core.Payload import Payload
from ccnpy.core.Tlv import Tlv


class ContentObjectTest(unittest.TestCase):
    def test_serialize(self):
        name = Name.from_uri('ccnx:/apple/pie')
        payload = Payload(array.array("B", [1, 3, 5, 7, 9]))
        dt = datetime.fromtimestamp(1560252745.906, UTC)
        fcid=9
        co = ContentObject.create_data(name=name, payload=payload, expiry_time=dt, final_chunk_id=fcid)
        name_tlv = co.name()
        payload_type_tlv = co.payload_type()
        expiry_tlv = co.expiry_time()
        fcid_tlv = co.final_chunk_id()
        byte_list= name_tlv.serialize()
        byte_list.extend(expiry_tlv.serialize())
        byte_list.extend(payload_type_tlv.serialize())
        byte_list.extend(payload.serialize())
        byte_list.extend(fcid_tlv.serialize())
        length = len(byte_list)
        expected = array.array("B", [0, 2, 0, length])
        expected.extend(byte_list)
        actual = co.serialize()
        self.assertEqual(expected, actual, "Incorrect serialization")

    def test_deserialize(self):
        wire_format = array.array('B', [0, 2, 0, 51,
                                        0, 0, 0, 16, 0, 1, 0, 5, 97, 112, 112, 108, 101, 0, 1, 0, 3, 112, 105, 101,
                                        0, 6, 0, 8, 0, 0, 1, 107, 70, 79, 136, 178,
                                        0, 5, 0, 1, 0,
                                        0, 1, 0, 5, 1, 3, 5, 7, 9,
                                        0, 7, 0, 1, 9])
        tlv = Tlv.deserialize(wire_format)
        actual = ContentObject.parse(tlv)

        name = Name.from_uri('ccnx:/apple/pie')
        payload = Payload(array.array("B", [1, 3, 5, 7, 9]))
        dt = datetime.fromtimestamp(1560252745.906, UTC)
        expected = ContentObject.create_data(name=name, payload=payload, expiry_time=dt, final_chunk_id=9)
        self.assertEqual(expected, actual, "Incorrect deserialization")

