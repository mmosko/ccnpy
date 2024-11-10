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
import getpass
from typing import Optional

from ccnpy.crypto.AeadKey import AeadKey, AeadGcm, AeadCcm
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.crypto.RsaKey import RsaKey
from ccnpy.crypto.RsaSha256 import RsaSha256Signer, RsaSha256Verifier
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor
from ccnpy.flic.aeadctx.AeadEncryptor import AeadEncryptor


def add_encryption_cli_args(parser):

    parser.add_argument('-k', dest="key_file", default=None,
                        help="RSA key in PEM format to sign the root manifest")
    parser.add_argument('-p', dest="key_pass", default=None,
                        help="RSA key password (otherwise will prompt)")

    parser.add_argument('--enc-key', dest="enc_key", default=None, help="AES encryption key (hex string)")
    parser.add_argument("--aes-mode", dest="aes_mode", default='GCM', choices=['GCM', 'CCM'], help="Encryption algorithm, default GCM")
    parser.add_argument('--key-num', dest="key_num", type=int, default=None,
                        help="Key number of pre-shared key (defaults to key hash)")
    parser.add_argument('--salt', dest="salt", type=lambda x: int(x,0), default=None,
                        help="Upto a 4-byte salt to include in the IV with the nonce.")

def aes_key_from_cli_args(args) -> Optional[AeadKey]:
    if args.enc_key is None:
        return None

    key_bytes = bytearray.fromhex(args.enc_key)
    if args.aes_mode == 'GCM':
        return AeadGcm(key=key_bytes)
    elif args.aes_mode == 'CCM':
        return AeadCcm(key=key_bytes)
    else:
        raise ValueError(f'aes_mode must be GCM or CCM, got {args.aes_mode}.')

def aead_encryptor_from_cli_args(args):
    if args.enc_key is not None:
        key = aes_key_from_cli_args(args)
        return AeadEncryptor(key=key, key_number=args.key_num, salt=args.salt)
    return None

def aead_decryptor_from_cli_args(args):
    if args.enc_key is not None:
        key = aes_key_from_cli_args(args)
        return AeadDecryptor(key=key, key_number=args.key_num, salt=args.salt)
    return None

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
            args.key_pass = getpass.getpass(prompt="Private key password")
        else:
            return

    if len(args.key_pass) == 0:
        args.key_pass = None

def create_keystore(args):
    keystore = InsecureKeystore()
    aes_key = aes_key_from_cli_args(args)
    if aes_key is not None:
        keystore.add_aes_key(args.key_num, aes_key, args.salt)

    if args.key_file is not None:
        keystore.add_rsa_key(name='default', key=RsaKey.load_pem_key(args.key_file, args.key_pass))

    return keystore
