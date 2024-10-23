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


class SizedPointer:
    """
    Represents a pointer along with its size in a Manifest, used while building a manifest
    """

    def __init__(self, content_object_hash, length):
        """
        :param content_object_hash: The name of the content object
        :param length: the application bytes
        """
        self._content_object_hash = content_object_hash
        self._length = length

    def content_object_hash(self):
        return self._content_object_hash

    def length(self):
        return self._length

    def file_name(self):
        b = self._content_object_hash.value().tobytes()
        return b.hex()
