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
from enum import Enum


class HpkeKdfIdentifiers(Enum):
    HKDF_SHA256 = 0x0001, 'HKDF-SHA256'
    HKDF_SHA384 = 0x0002, 'HKDF-SHA384'
    HKDF_SHA512 = 0x0003, 'HKDF-SHA512'

    def __init__(self, *args, **kwds):
        super().__init__(args[0])
        self.number = args[0]
        self.str_name = args[1]

    def __str__(self):
        return self.str_name

    def __repr__(self):
        return self.str_name

    @classmethod
    def parse(cls, name: str):
        for x in HpkeKdfIdentifiers:
            if x.str_name == name.upper():
                return x
        return KeyError(f'Not found: {name}')
