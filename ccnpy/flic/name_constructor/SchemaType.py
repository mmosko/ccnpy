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
from enum import StrEnum


class SchemaType(StrEnum):
    HASHED = 'hashed'
    PREFIX = 'prefix'
    SEGMENTED = 'segmented'

    @classmethod
    def parse(cls, value: str):
        v = value.lower()
        if v == cls.HASHED.value:
            return cls.HASHED
        if v == cls.PREFIX:
            return cls.PREFIX
        if v == cls.SEGMENTED:
            return cls.SEGMENTED
        raise ValueError(f'Cannot parse: {value}')