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


class Locators(ccnpy.TlvType):
    __type = 0x0012

    @staticmethod
    def class_type():
        return Locators.__type

    def __init__(self, final=False, links=None):
        """

        :param final:
        :param links:
        """
        ccnpy.TlvType.__init__(self, self.class_type())

        self._final = final
        self._links = links
        raise RuntimeError("Not Implemented")

    def __eq__(self, other):
        if self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        return "Locators(%r, %r)" % (self._final, self._links)

    def final(self):
        return self._final

    def links(self):
        return self._links

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def deserialize(cls, tlv):
        if tlv.type() != cls.class_type():
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())
        raise RuntimeError("Not Implemented")

