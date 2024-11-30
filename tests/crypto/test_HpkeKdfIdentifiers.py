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


from tests.ccnpy_testcase import CcnpyTestCase

from ccnpy.crypto.HpkeKdfIdentifiers import HpkeKdfIdentifiers


class HpkeKdfIdentifiersTest(CcnpyTestCase):
    def test_str(self):
        input = [HpkeKdfIdentifiers.HKDF_SHA256, HpkeKdfIdentifiers.HKDF_SHA384, HpkeKdfIdentifiers.HKDF_SHA512]
        output = ['HKDF-SHA256', 'HKDF-SHA384', 'HKDF-SHA512']
        for i in range(0, len(input)):
            actual = str(input[i])
            self.assertEqual(output[i], actual)

    def test_from_str(self):
        input = ['HKDF-SHA256', 'HKDF-SHA384', 'HKDF-SHA512']
        output = [HpkeKdfIdentifiers.HKDF_SHA256, HpkeKdfIdentifiers.HKDF_SHA384, HpkeKdfIdentifiers.HKDF_SHA512]
        for i in range(0, len(input)):
            actual = HpkeKdfIdentifiers.parse(input[i])
            self.assertEqual(output[i], actual)

    def test_repr(self):
        input = [HpkeKdfIdentifiers.HKDF_SHA256, HpkeKdfIdentifiers.HKDF_SHA384, HpkeKdfIdentifiers.HKDF_SHA512]
        output = ['HKDF-SHA256', 'HKDF-SHA384', 'HKDF-SHA512']
        for i in range(0, len(input)):
            actual = repr(input[i])
            self.assertEqual(output[i], actual)
