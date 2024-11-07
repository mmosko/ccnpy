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

from abc import abstractmethod

from ccnpy.core.Tlv import Tlv
from ccnpy.core.TlvType import TlvType


class SecurityCtx(TlvType):
    """
    Analogous to the ccnpy.ValidationAlg container.  It is an abstract intermediate class between
    TlvType and the concrete algorithms.

    ```SecurityCtx = TYPE LENGTH AlgorithmCtx
    AlgorithmCtx = AEADCtx / RsaKemCtx```
    """
    __type = 0x0001

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self):
        TlvType.__init__(self)

    @abstractmethod
    def __len__(self):
        pass

    @classmethod
    def parse(cls, tlv):
        # Due to circular reference between SecurityCtx and it's children, need
        # to defer the loading of the children
        from ..tlvs.AeadCtx import AeadCtx

        if tlv.type() != cls.class_type():
            raise ValueError("Incorrect TLV type %r" % tlv)

        inner_tlv = Tlv.deserialize(tlv.value())
        if inner_tlv.type() == AeadCtx.class_type():
            return AeadCtx.parse(inner_tlv)

        raise ValueError("Unsupported security context %r" % inner_tlv)

    @abstractmethod
    def serialize(self):
        pass
