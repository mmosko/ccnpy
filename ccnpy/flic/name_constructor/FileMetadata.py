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

from dataclasses import dataclass
from typing import List, Optional

from ccnpy.core.HashValue import HashValue
from ccnpy.core.Name import Name


@dataclass
class ChunkMetadata:
    """
    The input file is chunked sequentially.  This class maintains information about each chunk, which is used
    to construct the manifest.  The actual ContentObjects are written out to a Writer and not cached, so we could
    work on large files.
    """
    chunk_number: int               # the sequential chunk number
    payload_bytes: int              # The file bytes stored in the chunk
    content_object_hash: HashValue  # The ContentObjectHash (used for the Pointer)
    name: Optional[Name] = None     # The object name, or None for nameless

    def file_name(self):
        b = self.content_object_hash.value().tobytes()
        return b.hex()

@dataclass
class FileMetadata:
    """
    The input file is chunked sequentially.  This class maintains information about each chunk, which is used
    to construct the manifest.  The actual ContentObjects are written out to a Writer and not cached, so we could
    work on large files.
    """
    chunk_metadata: List[ChunkMetadata]
    total_bytes: int

    def __iter__(self):
        return FileMetadata.ReverseIterator(self)

    def __len__(self):
        return len(self.chunk_metadata)

    def __getitem__(self, item) -> ChunkMetadata:
        """

        :param item:
        :return: A ManifestPointer
        """
        return self.chunk_metadata[item]

    # def append(self, manifest_pointer: SizedPointer):
    #     if not isinstance(manifest_pointer, SizedPointer):
    #         raise TypeError("manifest_pointer must be ccnpy.flic.ManifestPointer")
    #
    #     self._chunks.append(manifest_pointer)

    def reverse_iterator(self):
        return self.__iter__()

    class ReverseIterator:
        def __init__(self, iterable):
            self._iterable = iterable
            self._offset = len(iterable) - 1

        def __next__(self):
            if self._offset < 0:
                raise StopIteration

            result = self._iterable[self._offset]
            self._offset -= 1
            return result

        def next(self) -> ChunkMetadata:
            return self.__next__()
