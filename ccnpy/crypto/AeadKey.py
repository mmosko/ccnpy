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


import array
import os
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM


class AeadKey(ABC):
    """
    Use either derived class `AeadGcm` or `AeadCcm`.
    """

    __salt_length = 128

    def __init__(self, key, algo):

        """

        :param key: a byte array
        """
        self._tag_len = 16
        self._key_bits = len(key) * 8
        self._algo = algo
        self._impl = algo(key)

    def __len__(self):
        return self._key_bits

    @classmethod
    @abstractmethod
    def generate(cls, bits):
        """
        Generate a secure key and return a SymmetricKey object

        :param bits: 128 or 256
        :return:
        """
        pass

    @staticmethod
    def nonce(bits=96):
        """
        Generate a randomized nonce, such as for use as an IV

        :param bits: 96 or 128 or 256
        :return:
        """
        if bits not in [96, 128, 256]:
            raise ValueError("bits must be 96 or 128 or 256")

        nonce = array.array("B", os.urandom(bits // 8))
        return nonce

    def encrypt(self, iv, plaintext, associated_data):
        """

        :param iv:
        :param plaintext:
        :param associated_data: (optional)
        :return: The tuple (ciphertext, authtag)
        """

        if isinstance(plaintext, array.array):
            plaintext = plaintext.tobytes()

        if isinstance(associated_data, array.array):
            associated_data = associated_data.tobytes()

        output = self._impl.encrypt(iv, plaintext, associated_data)
        ciphertext = array.array("B", output[:-self._tag_len])
        authtag = array.array("B", output[len(ciphertext):])
        return ciphertext, authtag

    def decrypt(self, iv, ciphertext, associated_data, auth_tag):
        """

        :param iv:
        :param ciphertext: a byte array
        :param associated_data: a byte array
        :param auth_tag: a byte array
        :return: The plaintext byte array or None (if authentication fails)
        """

        if isinstance(ciphertext, array.array):
            ciphertext = ciphertext.tobytes()

        if isinstance(auth_tag, array.array):
            auth_tag = auth_tag.tobytes()

        if isinstance(associated_data, array.array):
            associated_data = associated_data.tobytes()

        combined = ciphertext + auth_tag

        plaintext = None
        try:
            plaintext = self._impl.decrypt(iv, combined, associated_data)
        except InvalidTag:
            pass

        return array.array("B", plaintext)


class AeadGcm(AeadKey):
    def __init__(self, key):
        AeadKey.__init__(self, key, AESGCM)

    @classmethod
    def generate(cls, bits):
        """
        Generate a secure key and return a SymmetricKey object

        :param bits: 128 or 256
        :return:
        """
        if bits not in [128, 256]:
            raise ValueError("bits must be 128 or 256")

        key = AESGCM.generate_key(bit_length=bits)
        return cls(key)


class AeadCcm(AeadKey):
    def __init__(self, key):
        AeadKey.__init__(self, key, AESCCM)

    @classmethod
    def generate(cls, bits):
        """
        Generate a secure key and return a SymmetricKey object

        :param bits: 128 or 256
        :return:
        """
        if bits not in [128, 256]:
            raise ValueError("bits must be 128 or 256")

        key = AESCCM.generate_key(bit_length=bits)
        return cls(key)
