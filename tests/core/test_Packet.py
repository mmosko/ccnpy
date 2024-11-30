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
import tempfile
from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.core.ContentObject import ContentObject
from ccnpy.core.Name import Name
from ccnpy.core.Packet import Packet
from ccnpy.core.ValidationAlg import ValidationAlg_Crc32c
from ccnpy.crypto.Crc32c import Crc32cSigner


class PacketTest(CcnpyTestCase):
    def test_create_content_object(self):
        body = ContentObject.create_data(name=Name.from_uri('ccnx:/apple'), payload=[1, 2, 3, 4])
        packet = Packet.create_content_object(body)
        expected = array.array("B", [ 1,  1,  0, 38,
                                      0,  0,  0,  8,
                                      # T_CONTENT
                                      0,  2,  0, 26,
                                      # T_NAME
                                      0,  0,  0,  9,
                                      0,  1,  0,  5, 97, 112, 112, 108, 101,
                                      # T_PAYLOAD_TYPE
                                      0,  5,  0,  1,  0,
                                      # T_PAYLOAD
                                      0,  1,  0,  4,  1,  2,  3,  4])
        actual = packet.serialize()
        self.assertEqual(expected, actual)

    def test_create_signed_content_object(self):

        body = ContentObject.create_data(name=Name.from_uri('ccnx:/apple'), payload=[1, 2, 3, 4])

        signer = Crc32cSigner()
        validation_alg = ValidationAlg_Crc32c()
        validation_payload = signer.sign(body.serialize(), validation_alg.serialize())

        packet = Packet.create_signed_content_object(body, validation_alg, validation_payload)
        expected = array.array("B", [ 1,  1,  0, 54,
                                      0,  0,  0,  8,
                                      # T_CONTENT
                                      0,  2,  0, 26,
                                      # T_NAME
                                      0,  0,  0,  9,
                                      0,  1,  0,  5, 97, 112, 112, 108, 101,
                                      # T_PAYLOAD_TYPE
                                      0,  5,  0,  1,  0,
                                      # T_PAYLOAD
                                      0,  1,  0,  4,  1,  2,  3,  4,
                                      # Validation Alg
                                      0,  3,  0,  4,  0,  2,  0,  0,
                                      # Validation Payload
                                      0,  4,  0,  4,  0, 90, 226, 225])

        actual = packet.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize_signed_content_object(self):
        wire_format = array.array("B", [  1,  1,  0, 54,
                                          0,  0,  0,  8,
                                          # T_CONTENT
                                          0,  2,  0, 26,
                                          # T_NAME
                                          0,  0,  0,  9,
                                          0,  1,  0,  5, 97, 112, 112, 108, 101,
                                          # T_PAYLOAD_TYPE
                                          0,  5,  0,  1,  0,
                                          # T_PAYLOAD
                                          0,  1,  0,  4,  1,  2,  3,  4,
                                          # Validation Alg
                                          0,  3,  0,  4,  0,  2,  0,  0,
                                          # Validation Payload
                                          0,  4,  0,  4,  0, 90, 226, 225])
        actual = Packet.deserialize(wire_format)

        body = ContentObject.create_data(name=Name.from_uri('ccnx:/apple'), payload=[1, 2, 3, 4])

        signer = Crc32cSigner()
        validation_alg = ValidationAlg_Crc32c()
        validation_payload = signer.sign(body.serialize(), validation_alg.serialize())

        expected = Packet.create_signed_content_object(body, validation_alg, validation_payload)

        self.assertEqual(expected, actual)

    def test_save_load(self):
        body = ContentObject.create_data(name=Name.from_uri('ccnx:/apple'), payload=[1, 2, 3, 4])

        signer = Crc32cSigner()
        validation_alg = ValidationAlg_Crc32c()
        validation_payload = signer.sign(body.serialize(), validation_alg.serialize())

        packet = Packet.create_signed_content_object(body, validation_alg, validation_payload)

        tmp = tempfile.NamedTemporaryFile()
        packet.save(tmp.name)

        test = Packet.load(tmp.name)
        self.assertEqual(packet, test)
