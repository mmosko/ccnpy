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

from ccnpy.core.HashValue import HashValue
from ccnpy.flic.tree.FileChunks import FileChunks
from ccnpy.flic.tree.SizedPointer import SizedPointer


class FileChunksTest(CcnpyTestCase):

    def test_iterator(self):
        data = [
            SizedPointer(length=1, content_object_hash=HashValue(1, [1])),
            SizedPointer(length=2, content_object_hash=HashValue(2, [2])),
            SizedPointer(length=3, content_object_hash=HashValue(3, [3]))
        ]
        fc = FileChunks()
        fc.append(data[0])
        fc.append(data[1])
        fc.append(data[2])

        self.assertEqual(3, len(fc))
        actual = [x for x in fc]
        self.assertEqual(3, len(actual))
        self.assertEqual(data[0], actual[2])
        self.assertEqual(data[1], actual[1])
        self.assertEqual(data[2], actual[0])

    def test_must_be_sized_pointer(self):
        fc = FileChunks()
        with self.assertRaises(TypeError):
            fc.append(5)

