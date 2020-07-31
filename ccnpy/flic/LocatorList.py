#  Copyright 2019 Marc Mosko
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

import ccnpy
import ccnpy.flic


class LocatorList(ccnpy.TlvType):
    """
    Represents a list of Locators (links).
    """
    __type = 0x0003
    __final_type = 0x0001
    __locator_type = 0x0002

    @classmethod
    def class_type(cls):
        return cls.__type

    def __init__(self, final=False, locators=None):
        """

        :param final:
        :param locators: a list of ccnpy.flic.Locator
        """
        ccnpy.TlvType.__init__(self)

        if final is None:
            final = False

        self._final = final
        self._locators = locators

        tlvs = []
        if final:
            tlvs.append(ccnpy.Tlv(self.__final_type, []))

        if self._locators is not None:
            tlvs.extend(locators)

        self._tlv = ccnpy.Tlv(self.class_type(), tlvs)

    def __len__(self):
        return len(self._tlv)

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return "LocatorList: {final: %r, locs: %r}" % (self._final, self._locators)

    def final(self):
        return self._final

    def locators(self):
        return self._locators

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv)

        final = None
        locators = []
        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.Tlv.deserialize(tlv.value()[offset:])
            offset += len(inner_tlv)
            if inner_tlv.type() == cls.__final_type:
                assert final is None
                if inner_tlv.length() > 0:
                    raise ValueError("Final TLV should have 0 length")
                final = True
            elif inner_tlv.type() == ccnpy.flic.Locator.class_type():
                locator = ccnpy.flic.Locator.parse(inner_tlv)
                locators.append(locator)
            else:
                raise ValueError("Unsupported TLV %r" % inner_tlv)

        return cls(final=final, locators=locators)
