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

from ccnpy.flic.tlvs.SubtreeSize import SubtreeSize
from ccnpy.flic.tlvs.LeafDigest import LeafDigest
from ccnpy.flic.tlvs.LeafSize import LeafSize
from ccnpy.flic.tlvs.StartSegmentId import StartSegmentId
from ccnpy.flic.tlvs.SubtreeDigest import SubtreeDigest
from ccnpy.flic.tlvs.NcId import NcId
from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType
from ccnpy.exceptions.CannotParseError import CannotParseError
from ccnpy.exceptions.ParseError import ParseError


class GroupData(TlvType):
    """
    TODO: Should extend NodeData instead of repeating all the code
    """
    __type = 0x0001
    __subtree_digest_type = 0x0002

    DEBUG = False

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self,
                 subtree_size: Optional[SubtreeSize] = None,
                 subtree_digest: Optional[SubtreeDigest] =None,
                 leaf_size: Optional[LeafSize] = None,
                 leaf_digest: Optional[LeafDigest] = None,
                 nc_id: Optional[NcId] = None,
                 start_segment_id: Optional[StartSegmentId] = None):
        """

        :param subtree_size: Total bytes in direct or indirect pointers
        :param subtree_digest: Hash of all content under group
        :param leaf_size: Total application bytes in direct pointers
        :param leaf_digest: Hash of application data directly under group
        :param nc_id: Name constructor ID for group
        :param start_segment_id: The starting segment ID for pointers under group.
        """
        TlvType.__init__(self)

        if subtree_size is not None and not isinstance(subtree_size, SubtreeSize):
            raise TypeError("subtree_size, if present, must be ccnpy.core.flic.SubtreeSize")

        if subtree_digest is not None and not isinstance(subtree_digest, SubtreeDigest):
            raise TypeError("subtree_digest, if present, must be SubtreeDigest")

        self._subtree_size = subtree_size
        self._subtree_digest = subtree_digest
        self._leaf_size = leaf_size
        self._leaf_digest = leaf_digest
        self._nc_id = nc_id
        self._start_segment_id = start_segment_id

        # It's OK to have None values in the array.  The Tlv constructor will ignore Nones.
        tlvs = [self._subtree_size, self._subtree_digest,
                self._leaf_size, self._leaf_digest,
                self._nc_id, self._start_segment_id]
        self._tlv = Tlv(self.class_type(), tlvs)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return ("GroupData: {%r, %r, %r, %r, %r, %r}" %
                (self._subtree_size, self._subtree_digest,
                 self._leaf_size, self._leaf_digest,
                 self._nc_id, self._start_segment_id))

    def subtree_size(self):
        return self._subtree_size

    def subtree_digest(self):
        return self._subtree_digest

    def leaf_size(self):
        return self._leaf_size

    def leaf_digest(self):
        return self._leaf_digest

    def nc_id(self):
        return self._nc_id

    def start_segment_id(self):
        return self._start_segment_id

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def auto_parse(cls, tlv, name_class_pairs):
        """
        `name_class_pairs` is a list of (str, class) pairs.  The string is the argument name for the
         class constructor and the class is the corresponding TlvType.  `auto_parse` will go through the
        `tlv` nesting and extract out the available classes.  it will then return a dictionary
        `Dict[str, tlvtype]` that is used to initalize the class.
        """

        parser_lookup = {y.class_type(): (x, y) for x,y in name_class_pairs}
        values = {x: None for x,y in name_class_pairs}

        offset = 0
        while offset < tlv.length():
            try:
                inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            except ParseError as e:
                print(f'Error parsing {tlv.value()} at offset {offset}: {e}')
                raise

            offset += len(inner_tlv)

            try:
                name_class = parser_lookup[inner_tlv.type()]
                arg_name = name_class[0]
                clazz = name_class[1]
                assert values[arg_name] is None
                values[arg_name] = clazz.parse(inner_tlv)
            except KeyError:
                raise ParseError("Unsupported GroupData TLV type %r" % inner_tlv)
        return values

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise CannotParseError("Incorrect TLV type %r" % tlv.type())

        if cls.DEBUG:
            print(f'GroupData parsing Tlv: {tlv}')

        classes = [ ('subtree_size', SubtreeSize),
                   ('subtree_digest', SubtreeDigest),
                   ('leaf_size', LeafSize),
                   ('leaf_digest', LeafDigest),
                   ('nc_id', NcId),
                   ('start_segment_id', StartSegmentId) ]

        values = cls.auto_parse(tlv, classes)
        return cls(**values)
