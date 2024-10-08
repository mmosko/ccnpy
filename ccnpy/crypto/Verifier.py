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


class Verifier(ABC):
    """
    Abstract class used to sign a Packet.
    """
    @abstractmethod
    def verify(self, *buffers, validation_payload):
        """
        Checks if the validation_payload checks out on the buffer
        :param buffers: One or more buffers to concatenate and verify
        :param validation_payload: The ValidationPayload to compare
        :return: True or False
        """
        pass
