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


@dataclass
class FileMetadata:
    """
    The input file is chunked sequentially.  This class maintains information about each chunk, which is used
    to construct the manifest.  The actual ContentObjects are written out to a Writer and not cached, so we could
    work on large files.
    """
    chunk_metadata: List[ChunkMetadata]
    total_bytes: int
