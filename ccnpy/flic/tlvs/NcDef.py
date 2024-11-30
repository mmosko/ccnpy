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
import logging

from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from .NcId import NcId
from .NcSchema import NcSchema
from .TlvNumbers import TlvNumbers
from ...exceptions.CannotParseError import CannotParseError


class NcDef(TlvType):
    """
    Name Constructor Definition TLV.

        NcDef = TYPE LENGTH NcId NcSchema
    """
    logger = logging.getLogger(__name__)

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_NCDEF

    def __init__(self, nc_id: NcId, schema: NcSchema):
        TlvType.__init__(self)
        self._nc_id = nc_id
        self._schema = schema
        self._tlv = Tlv(self.class_type(), [self._nc_id, self._schema])

    def nc_id(self) -> NcId:
        return self._nc_id

    def schema(self) -> NcSchema:
        return self._schema

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return f"NCDEF: ({self._nc_id}, {self._schema})"

    def __eq__(self, other):
        if not isinstance(other, NcDef):
            return False
        return self._tlv == other._tlv

    @classmethod
    def parse(cls, tlv):
        cls.logger.debug('parsing: %s', tlv)

        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        nc_id = schema = None

        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == NcId.class_type():
                assert nc_id is None
                nc_id = NcId.parse(inner_tlv)
            else:
                assert schema is None
                schema = NcSchema.parse(inner_tlv)

        return cls(nc_id=nc_id, schema=schema)

    def serialize(self):
        return self._tlv.serialize()
