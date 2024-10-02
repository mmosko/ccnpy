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


class Signer(ABC):
    """
    Abstract class used to sign a Packet.
    """
    @abstractmethod
    def sign(self, *buffers):
        """
        Returns the ValidationPayload
        :param buffers: one or more buffers (e.g. sign(body, validation_alg))
        :return:
        """
        pass

    @abstractmethod
    def keyid(self):
        """
        Returns the signer's public key ID.  Some algorithms may not have a KeyId.

        :return: A HashValue, may be None
        """
        pass

    @abstractmethod
    def validation_alg(self, include_public_key=False, key_link=None, signature_time=None):
        """
        Generate a ValidationAlg for this key.  If `include_public_key` is True, embed the public key in
        the ValidationAlg.  If key_link is a ccnpy.KeyLink, add it to the ValidationAlg.  If signature_time
        is None, use the current UTC time, othewise use the provided signature_time.

        Note: not all signers support all options.

        :param include_public_key: True to embed the signer's public key
        :param key_link: (optional) a ccnpy.KeyLink
        :param signature_time: a datetime or a ccnpy.SignatureTime or None to use current UTC time.
        :return: A ValidationAlg appropriate to the signer
        """
        pass