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


class TlvNumbers:
    """
    A definition of all the IANA numbers used by FLIC.

    You should not use thie file.  It is meant to be used to populate the `class_type()` methods of each Tlv class.
    You should use something like `LeafDigest.class_type()` to know its TlvType, not look in here.  Really, it is
    very unlikely that you should need to know the Tlv numbers, as each class encapsulates its own serialize
    and parse.
    """
    T_FLIC_MANIFEST = 0x0000

    # top-level manifest types
    T_SECURITY_CTX = 0x0000
    T_NODE = 0x0001
    T_ENCRYPTED_NODE = 0x0002
    T_AUTH_TAG = 0x0003

    # security contextx
    T_AEAD_CTX = 0x0000
    T_RSAOAEP_CTX = 0x0001

    # Node types
    T_NODE_DATA = 0x0000
    T_HASH_GROUP = 0x0001
    T_SUBTREE_SIZE = 0x0002
    T_SUBTREE_DIGEST = 0x0003
    T_NCDEF = 0x0004
    T_NCID = 0x0005
    T_LOCATORS = 0x0006
    T_PTRS = 0x0007
    T_ANNOTATED_PTRS = 0x0008
    T_PTR_BLOCK = 0x0009
    T_PTR = 0x000A
    T_GROUP_DATA = 0x000B

    T_HashSchema = 0x0010
    T_PrefixSchema = 0x0011
    T_SegmentedSchema = 0x0012

    T_ORG = 0x0FFF

    # NcSchema types
    T_PROTOCOL_FLAGS = 0x0001
    T_SUFFIX_TYPE = 0x0002
    T_LINK = 0x000D

    # Group Data
    T_LEAF_SIZE = 0x0000
    T_LEAF_DIGEST = 0x0001
    T_START_SEGMENT_ID = 0x0004

    # Security Context
    T_KEYNUM = 0x0000
    T_NONCE = 0x0001
    T_AEADMode = 0x0002
    T_HASH_ALG = 0x0003
    T_WRAPPED_KEY = 0x0004
    T_KDF_DATA = 0x0005
    T_KDF_ALG = 0x0006
    T_KDF_INFO = 0x0007
    T_KEYID = 0x0009
    T_KEYLINK = 0x000E



