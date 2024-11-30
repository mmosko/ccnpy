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
from typing import Optional

from .LeafDigest import LeafDigest
from .LeafSize import LeafSize
from .NcId import NcId
from .StartSegmentId import StartSegmentId
from .SubtreeDigest import SubtreeDigest
from .SubtreeSize import SubtreeSize
from .TlvNumbers import TlvNumbers
from ...core.Tlv import Tlv
from ...core.TlvType import TlvType


class GroupData(TlvType):
    """
    TODO: Should extend NodeData instead of repeating all the code
    """
    logger = logging.getLogger(__name__)

    @classmethod
    def class_type(cls):
        return TlvNumbers.T_GROUP_DATA

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
    def parse(cls, tlv):
        cls.logger.debug('parsing Tlv: %s', tlv)

        classes = [ ('subtree_size', SubtreeSize),
                   ('subtree_digest', SubtreeDigest),
                   ('leaf_size', LeafSize),
                   ('leaf_digest', LeafDigest),
                   ('nc_id', NcId),
                   ('start_segment_id', StartSegmentId) ]

        values = cls.auto_parse(tlv, classes)
        return cls(**values)

