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
import argparse
import getpass
import logging
import uuid
from typing import Optional

from ccnpy.crypto.AeadKey import AeadKey, AeadGcm, AeadCcm
from ccnpy.crypto.HpkeKdfIdentifiers import HpkeKdfIdentifiers
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256Signer, RsaSha256Verifier
from ccnpy.flic.RsaOaepCtx.RsaOaepEncryptor import RsaOaepEncryptor
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor
from ccnpy.flic.aeadctx.AeadParameters import AeadParameters
from ccnpy.flic.tlvs.KdfAlg import KdfAlg
from ccnpy.flic.tlvs.KdfData import KdfData
from ccnpy.flic.tlvs.KdfInfo import KdfInfo
from ccnpy.flic.tlvs.KeyNumber import KeyNumber


logger = logging.getLogger(__name__)


def _str_to_array(value: str):
    """
    Accept a string in the forms "0xabcd..." or "abcd..." (both in hex) and output
    an array['B', ...]
    """
    if value.startswith('0x'):
        offset=2
    else:
        offset=0

    return bytes.fromhex(value[offset:])

def add_encryption_cli_args(parser):

    parser.add_argument('-k', dest="key_file", default=None,
                        help="RSA key in PEM format to sign the root manifest")
    parser.add_argument('-p', dest="key_pass", default=None,
                        help="RSA key password (otherwise will prompt)")

    parser.add_argument('--wrap-key', dest="wrap_key", default=None, help="Wrapping key for RSA-OAEP mode.")
    parser.add_argument('--wrap-pass', dest="wrap_pass", default=None, help="Wrapping key key password (otherwise will prompt).")

    parser.add_argument('--enc-key', dest="enc_key",
                        type=_str_to_array,
                        default=None, help="AES encryption key (hex string)")
    parser.add_argument("--aes-mode", dest="aes_mode", default='GCM',
                        type=lambda x: x.upper(),
                        choices=['GCM', 'CCM'], help="Encryption algorithm, default GCM")
    parser.add_argument('--key-num', dest="key_num", type=KeyNumber, default=None,
                        help="Key number of pre-shared key (defaults to key hash)")
    parser.add_argument('--salt', dest="salt", type=lambda x: int(x,0), default=None,
                        help="Upto a 4-byte salt to include in the IV with the nonce.")

    parser.add_argument('--kdf', dest="kdf_alg", type=lambda x: HpkeKdfIdentifiers.parse(x),
                        choices=[HpkeKdfIdentifiers.HKDF_SHA256, HpkeKdfIdentifiers.HKDF_SHA384, HpkeKdfIdentifiers.HKDF_SHA512],
                        default=None,
                        help="Use a KDF")
    parser.add_argument('--kdf-info', dest="kdf_info", type=lambda x: KdfInfo(x),
                        default=None,
                        help="KDF INFO string (ascii or 0x hex string)")
    parser.add_argument('--kdf-uuid', dest="kdf_uuid", default=False, action=argparse.BooleanOptionalAction,
                        help="Use a Type 1 UUID for the KdfInfo (overrides --kdf-info)")
    parser.add_argument('--kdf-salt', dest="kdf_salt", type=lambda x: int(x,0), default=None,
                        help="Upto a 4-byte salt to include in the KDF function (do not use with RSA-OAEP).")


def aes_key_from_cli_args(args) -> Optional[AeadKey]:
    if args.enc_key is None:
        return None

    if args.aes_mode == 'GCM':
        return AeadGcm(key=args.enc_key)
    elif args.aes_mode == 'CCM':
        return AeadCcm(key=args.enc_key)
    else:
        raise ValueError(f'aes_mode must be GCM or CCM, got {args.aes_mode}.')

def kdf_data_from_cli(args) -> Optional[KdfData]:
    if args.kdf_uuid:
        args.kdf_info = KdfInfo(uuid.uuid1())

    if args.kdf_alg is not None:
        return KdfData(KdfAlg(args.kdf_alg), args.kdf_info)
    else:
        return None

def aead_parameters_from_cli(args):
    key = aes_key_from_cli_args(args)
    params = AeadParameters(
        key=key,
        key_number=args.key_num,
        aead_salt=args.salt,
        kdf_data=kdf_data_from_cli(args),
        kdf_salt=args.kdf_salt)

    logger.debug(params)

    return params

def aead_encryptor_from_cli_args(args) -> Optional[AeadEncryptor]:
    if args.enc_key is not None:
        return AeadEncryptor(aead_parameters_from_cli(args))
    return None

def aead_decryptor_from_cli_args(args) -> Optional[AeadDecryptor]:
    if args.enc_key is not None:
        return AeadDecryptor(aead_parameters_from_cli(args))
    return None

def rsa_oaep_encryptor_from_cli_args(args):
    if args.wrap_key is None:
        raise ValueError("You must specify a wrapping key for RSA-OAEP mode.")

    wrapping_key = RsaKey.load_pem_key(args.wrap_key, args.wrap_pass)
    if args.enc_key is None:
        encryptor = RsaOaepEncryptor.create_with_new_content_key(wrapping_key=wrapping_key, kdf_data=kdf_data_from_cli(args))
    else:
        encryptor = RsaOaepEncryptor(wrapping_key=wrapping_key, params=aead_parameters_from_cli(args))
    logger.debug(encryptor)
    return encryptor

def encryptor_from_cli_args(args):
    if args.wrap_key is None:
        return aead_encryptor_from_cli_args(args)
    else:
        return rsa_oaep_encryptor_from_cli_args(args)

def rsa_signer_from_cli_args(args):
    if args.key_file is not None:
        signing_key = RsaKey.load_pem_key(args.key_file, args.key_pass)
        return RsaSha256Signer(signing_key)
    return None

def rsa_verifier_from_cli_args(args):
    if args.key_file is not None:
        public_key = RsaKey.load_pem_key(args.key_file, args.key_pass)
        return RsaSha256Verifier(public_key)
    return None

def fixup_key_password(args, ask_for_pass: bool = True):
    if args.key_pass is None:
        if ask_for_pass:
            args.key_pass = getpass.getpass(prompt="Signing private key password")
            if len(args.key_pass) == 0:
                args.key_pass = None

    if args.wrap_key is not None and args.wrap_pass is None:
        if ask_for_pass:
            args.wrap_pass = getpass.getpass(prompt="Wrapping key password")
            if len(args.wrap_pass) == 0:
                args.wrap_pass = None

def create_keystore(args):
    keystore = InsecureKeystore()
    aead_params = aead_parameters_from_cli(args)
    if aead_params.key is not None:
        keystore.add_aes_key(aead_params)

    if args.key_file is not None:
        keystore.add_rsa_key(name='default', key=RsaKey.load_pem_key(args.key_file, args.key_pass))

    if args.wrap_key is not None:
        keystore.add_rsa_key(name='wrap', key=RsaKey.load_pem_key(args.wrap_key, args.wrap_pass))

    return keystore
