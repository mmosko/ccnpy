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

from ..SecurityCtx import SecurityCtx
from ...core.DisplayFormatter import DisplayFormatter
from ...core.Tlv import Tlv


class PresharedKeyCtx(SecurityCtx):
    """
    The security context for a PresharedKey encryption.  This is analogous to a ValidationAlg implementation,
    such as ccnpy.ValidationAlg_RsaSha256.  This class is used by the `PresharedKey` class and typically
    the user does not need to touch it.

    Typically, you will use `PresharedKeyCtx.create_aes_gcm_256(...)` or `PresharedKeyData.parse(...)`.
    """
    __T_PRESHARED = 0x0001
    __T_KEYNUM = 0x0001
    __T_IV = 0x0002
    __T_MODE = 0x0003

    __MODE_AES_GCM_128 = 1
    __MODE_AES_GCM_256 = 2
    __allowed_modes = [__MODE_AES_GCM_128, __MODE_AES_GCM_256]

    @classmethod
    def class_type(cls):
        return cls.__T_PRESHARED

    @classmethod
    def create_aes_gcm_128(cls, key_number, iv):
        return cls(key_number, iv, cls.__MODE_AES_GCM_128)

    @classmethod
    def create_aes_gcm_256(cls, key_number, iv):
        return cls(key_number, iv, cls.__MODE_AES_GCM_256)

    def __mode_string(self):
        if self._mode == self.__MODE_AES_GCM_128:
            return "AES-GCM-128"
        if self._mode == self.__MODE_AES_GCM_256:
            return "AES-GCM-256"
        raise ValueError("Unsupported mode %r" % self._mode)

    def __init__(self, key_number, iv, mode):
        """

        :param key_number: An integer
        :param iv: A byte array
        :param mode: One of the allowed modes (use a class create_x method to create)
        """
        SecurityCtx.__init__(self)
        self._key_number = key_number
        self._iv = iv
        self._mode = mode

        key_tlv = Tlv(self.__T_KEYNUM, Tlv.number_to_array(self._key_number))
        iv_tlv = Tlv(self.__T_IV, self._iv)
        mode_tlv = Tlv.create_uint8(self.__T_MODE, self._mode)

        self._tlv = Tlv(SecurityCtx.class_type(),
                        Tlv(self.class_type(), [key_tlv, iv_tlv, mode_tlv]))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __len__(self):
        return len(self._tlv)

    def __repr__(self):
        return "PSK: {kn: %r, iv: %r, mode: %r}" % (self._key_number,
                                                    DisplayFormatter.hexlify(self._iv),
                                                    self.__mode_string())

    @classmethod
    def parse(cls, tlv):
        if tlv.type() != cls.class_type():
            raise ValueError("Incorrect TLV type %r" % tlv.type())

        key_number = iv = mode = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = Tlv.deserialize(tlv.value()[offset:])
            if inner_tlv.type() == cls.__T_KEYNUM:
                assert key_number is None
                key_number = inner_tlv.value_as_number()
            elif inner_tlv.type() == cls.__T_IV:
                assert iv is None
                iv = inner_tlv.value()
            elif inner_tlv.type() == cls.__T_MODE:
                assert mode is None
                mode = inner_tlv.value_as_number()
                if mode not in cls.__allowed_modes:
                    raise ValueError("Unsupported mode %r" % inner_tlv)
            else:
                raise ValueError("Unsupported TLV %r" % inner_tlv)
            offset += len(inner_tlv)

        return cls(key_number=key_number, iv=iv, mode=mode)

    def serialize(self):
        return self._tlv.serialize()

    def is_aes_gcm_128(self):
        return self._mode == self.__MODE_AES_GCM_128

    def is_aes_gcm_256(self):
        return self._mode == self.__MODE_AES_GCM_256

    def iv(self):
        return self._iv

    def key_number(self):
        return self._key_number
