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
from typing import Iterable

from .SizedPointer import SizedPointer


class FileChunks:
    def __init__(self):
        self._chunks = []

    def __iter__(self):
        return FileChunks.ReverseIterator(self)

    def __len__(self):
        return len(self._chunks)

    def __getitem__(self, item):
        """

        :param item:
        :return: A ManifestPointer
        """
        return self._chunks[item]

    def append(self, manifest_pointer: SizedPointer):
        if not isinstance(manifest_pointer, SizedPointer):
            raise TypeError("manifest_pointer must be ccnpy.flic.ManifestPointer")

        self._chunks.append(manifest_pointer)

    def reverse_iterator(self):
        return self.__iter__()

    class ReverseIterator(Iterable):
        def __iter__(self):
            return self

        def __init__(self, iterable):
            self._iterable = iterable
            self._offset = len(iterable) - 1

        def __next__(self):
            if self._offset < 0:
                raise StopIteration

            result = self._iterable[self._offset]
            self._offset -= 1
            return result

        def next(self):
            return self.__next__()
