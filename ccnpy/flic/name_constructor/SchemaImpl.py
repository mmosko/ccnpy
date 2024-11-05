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

from abc import ABC, abstractmethod
from typing import BinaryIO, Optional

from .FileMetadata import FileMetadata
from .NcId import NcId
from ..Locators import Locators
from ...core.Name import Name
from ...core.Packet import PacketWriter


class SchemaImpl(ABC):
    """
    The NcSchema-derived classes define the Manifest TLVs for different schemas.  The `SchemaImpl` derived
    classes implement the schemas.
    """

    def __init__(self):
        self._next_chunk_id = 0

    def _get_and_increment_next_chunk_id(self) -> int:
        next_chunk_id = self._next_chunk_id
        self._next_chunk_id += 1
        return next_chunk_id

    def get_next_name(self) -> Optional[Name]:
        """
        Returns the name of the next object, which maybe None for hash schema.  This metnod increments an internal
        counter to track the generated names.
        """
        next_chunk_id = self._get_and_increment_next_chunk_id()
        return self.get_name(chunk_id=next_chunk_id)

    @abstractmethod
    def nc_id(self) -> NcId:
        pass

    @abstractmethod
    def locators(self) -> Optional[Locators]:
        """The locators associated with this schema, which may be None"""
        pass

    @abstractmethod
    def chunk_data(self, data_input: BinaryIO, packet_output: PacketWriter) -> FileMetadata:
        pass

    @abstractmethod
    def get_name(self, chunk_id) -> Optional[Name]:
        """
        Returns the CCNx name of the object at `chunk_id` offset.
        """
        pass

