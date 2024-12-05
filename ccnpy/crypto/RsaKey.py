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
import hashlib
import logging
import math
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils

from ..core.HashValue import HashValue


class RsaKey:
    """
    TODO: Need a way to create an RSA key from the DER encoded public key
    """
    logger = logging.getLogger(__name__)
    _SHA256_OVERHEAD = 66 #RSA OAEP overhead for sha 256 hash

    def __init__(self, pem_key, password=None):
        """
        Pass in one of (A) encrypted private key, (B) unencrypted private key, (C) public key
        all in PEM format.

        If a private key is passed in, the RsaKey can sign and verify.  If a public key
        is passed in, RsaKey can only verify.

        :param pem_key: A PEM private or public key
        :param password:
        """
        self._private_key = None
        self._public_key = None

        if pem_key.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n'):
            self.__initialize_private_key(pem_key, password)
        elif pem_key.startswith(b'-----BEGIN RSA PRIVATE KEY-----\n'):
            self.__initialize_private_key(pem_key, password)
        elif pem_key.startswith(b'-----BEGIN PRIVATE KEY-----\n'):
            self.__initialize_private_key(pem_key, password)
        elif pem_key.startswith(b'-----BEGIN PUBLIC KEY-----\n'):
            self.__initialize_public_key(pem_key)
        else:
            raise RuntimeError("Could not determine type of key from PEM file")

        if self.logger.isEnabledFor(logging.DEBUG):
            if isinstance(self._public_key, rsa.RSAPublicKey):
                self.logger.debug('RSA public keysize: %s', self._public_key.key_size)

    def __initialize_private_key(self, pem_key, password):
        if password is not None and len(password) == 0:
            password = None
        self._private_key = serialization.load_pem_private_key(
                                pem_key,
                                password=password,
                                backend=default_backend())
        self._public_key = self._private_key.public_key()

    def __initialize_public_key(self, pem_key):
        self._public_key = serialization.load_pem_public_key(
                                pem_key,
                                backend=default_backend())

    def __repr__(self):
        return "RsaKey: {%r, %r}" % (self._private_key, self._public_key)

    def has_private_key(self):
        """

        :return: True if RsaKey has a private key
        """
        return self._private_key is not None

    def has_public_key(self):
        """

        :return: True if RsaKey has a public key
        """
        return self._public_key is not None

    def save_private_key(self, filename, password):
        """
        Serialize the key to the filesystem and encrypt it PKCS #8 with a password

        :param filename: The filename to save it as
        :param password: A byte string (i.e. b'password')
        :return:
        """
        if self._private_key is None:
            raise ValueError("RsaKey does not have a private key")

        pem = self._private_key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.PKCS8,
                encryption_algorithm = serialization.BestAvailableEncryption(password))

        with open(filename, "wb") as key_file:
            key_file.write(pem)

    def public_key_pem(self):
        """

        :return: PEM encoded public key as a  string
        """
        if self._public_key is None:
            raise ValueError("RsaKey does not have a public key")

        pem = self._public_key.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem

    def public_key_der(self):
        """

        :return: DER encoded public key as a  string
        """
        if self._public_key is None:
            raise ValueError("RsaKey does not have a public key")

        der = self._public_key.public_bytes(
                encoding = serialization.Encoding.DER,
                format = serialization.PublicFormat.SubjectPublicKeyInfo)
        return der

    @staticmethod
    def __create_padding(use_pss=False):
        if use_pss:
            pad = padding.PSS(
                            mgf = padding.MGF1(hashes.SHA256()),
                            salt_length = padding.PSS.MAX_LENGTH
                        )
        else:
            pad = padding.PKCS1v15()
        return pad

    def sign(self, *buffers, use_pss_padding=False):
        """

        :param buffers: One or more buffers to sign
        :param use_pss_padding: Use PSS padding with MGF1, otherwise use PKCS1 v1.5
        :return: A byte array
        """
        if self._private_key is None:
            raise ValueError("RsaKey does not have a private key")

        hash_function = hashes.SHA256()
        hasher = hashes.Hash(hash_function, default_backend())
        for buffer in buffers:
            hasher.update(buffer)
        digest = hasher.finalize()

        signature = self._private_key.sign(
                        digest,
                        self.__create_padding(use_pss_padding),
                        utils.Prehashed(hash_function)
                        )
        return array.array("B", signature)

    def verify(self, *buffers, signature, use_pss_padding=False):
        if self._public_key is None:
            raise ValueError("RsaKey does not have a public key")

        if isinstance(signature, array.array):
            signature = signature.tobytes()

        result = False

        try:
            hash_function = hashes.SHA256()
            hasher = hashes.Hash(hash_function, default_backend())
            for buffer in buffers:
                hasher.update(buffer)
            digest = hasher.finalize()

            self._public_key.verify(
                signature,
                digest,
                self.__create_padding(use_pss_padding),
                utils.Prehashed(hash_function)
            )
            result = True
        except InvalidSignature:
            pass

        return result

    def encrypt_oaep_sha256(self, plaintext: bytes, label: Optional[bytes] = None):
        """
        Encrypt the plain text using RSA-OAEP padding with SHA256 and MGF1.

        :param plaintext: Bytes or an array
        :param label: Optional label (additional info) for OAEP padding
        :returns: An array
        """
        if isinstance(plaintext, array.array):
            plaintext = plaintext.tobytes()

        max_encryption_size = math.ceil(self._public_key.key_size / 8) - self._SHA256_OVERHEAD
        if len(plaintext) > max_encryption_size:
            required_key_size = (len(plaintext) + self._SHA256_OVERHEAD) * 8
            raise ValueError(f"The RSA public key is {self._public_key.key_size} bits, but the plaintext of {len(plaintext)} bytes needs a key of at least {required_key_size} bits")

        output = self._public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label
            )
        )

        return array.array("B", output)

    def decrypt_oaep_sha256(self, cyphertext: bytes, label: Optional[bytes] = None):
        """
        Decrypt the message using RSA-OAEP with SHA256 and MGF1

        :param cyphertext: Bytes or an array
        :returns: An array
        """
        if isinstance(cyphertext, array.array):
            cyphertext = cyphertext.tobytes()

        output = self._private_key.decrypt(
            cyphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label
            )
        )

        return array.array("B", output)

    @classmethod
    def generate_private_key(cls, key_length=4096):
        # Creates an RsaPrivateKey object
        private_key = rsa.generate_private_key(
                        public_exponent = 65537,
                        key_size = key_length,
                        backend = default_backend())

        pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                #format=serialization.PrivateFormat.PKCS8,
                #encryption_algorithm=serialization.BestAvailableEncryption(b'not_so_secert'))
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())
        return cls(pem_key=pem)

    @classmethod
    def load_pem_key(cls, filename, password=None):
        """
        loads a PEM key from the file system.  It may be either a private key or a public key.
        A private key may be encrypted, so pass the correct password.

        :param filename:
        :return:
        """
        with open(filename, "rb") as key_file:
            pem = key_file.read()
            return cls(pem, password)

    def keyid(self) -> HashValue:
        """
        sha256 of the public key in DER format returned in a ccnpy.HashValue
        :return:
        """
        der = self.public_key_der()
        h = hashlib.sha256()
        h.update(der)
        digest = h.digest()
        tlv = HashValue.create_sha256(digest)
        return tlv
