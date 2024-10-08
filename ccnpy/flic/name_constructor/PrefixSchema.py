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
from typing import Optional

from .LocatorSchema import LocatorSchema
from .ProtocolFlags import ProtocolFlags
from .ProtocolFlagsSchema import ProtocolFlagsSchema
from ..Locators import Locators


class PrefixSchema(LocatorSchema):
    __T_PREFIX_SCHEMA = 0x0003

    @classmethod
    def class_type(cls):
        return cls.__T_PREFIX_SCHEMA

    def __init__(self, locators: Locators, flags: Optional[ProtocolFlags] = None):
        LocatorSchema.__init__(self, locators=locators, flags=flags)

