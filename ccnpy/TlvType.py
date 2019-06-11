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



class TlvType:
    T_INTEREST = 0x0001
    T_OBJECT = 0x0002
    T_VALIDATION_ALG = 0x0003
    T_VALIDATION_PAYLOAD = 0x0004
    T_MANIFEST = 0x0005

    T_NAMESEGMENT = 0x0001
    T_NAME = 0x0000
    T_PAYLOAD = 0x0001
    T_KEYIDRESTR = 0x0002
    T_OBJHASHRESTR = 0x0003
    T_PAYLDTYPE = 0x0005
    T_EXPIRY = 0x0006
    T_RSA_SHA256 = 0x0004
    T_EC_SECP_256K1 = 0x0006
    T_PAD = 0x0FFE
    T_KEYID = 0x0009
    T_PUBLICKEYLOC = 0x000A
    T_LINK = 0x000D
    T_KEYLINK = 0x000E
    T_SIGTIME = 0x000F
    T_SHA_256 = 0x0001

    """
    superclass for objects that are TLV types
    """
    def __init__(self, type_number):
        self._type_number = type_number

    def type_number(self):
        return self._type_number
