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
from typing import BinaryIO


class MockReader:
    def __init__(self, data):
        self.data = data
        self._offset = 0

    def read(self, n=-1):
        if self._offset >= len(self.data):
            return b''

        if n < 0:
            self._offset = len(self.data)
            return self.data[self._offset:]
        else:
            start = self._offset
            tail = min(len(self.data), start + n)
            self._offset += tail - start
            return self.data[start:tail]
