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
from ccnpy.core.ValidationAlg import ValidationAlg_Crc32c, ValidationAlg_RsaSha256
from ccnpy.crypto.Crc32c import Crc32cVerifier
from ccnpy.crypto.DecryptionError import DecryptionError
from ccnpy.crypto.InsecureKeystore import InsecureKeystore, KeyIdNotFoundError, KeyNumberNotFoundError
from ccnpy.crypto.RsaSha256 import RsaSha256Verifier
from ccnpy.flic.RsaOaepCtx.RsaOaepDecryptor import RsaOaepDecryptor
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor
from ccnpy.flic.tlvs.AeadCtx import AeadCtx
from ccnpy.flic.tlvs.Manifest import Manifest
from ccnpy.flic.tlvs.RsaOaepCtx import RsaOaepCtx

__static_crc32c_verifier = Crc32cVerifier()

def validate_packet(keystore: InsecureKeystore, packet):
    alg = packet.validation_alg()
    if alg is None:
        return

    if isinstance(alg, ValidationAlg_Crc32c):
        # use a pre-allocated one, no need to allocate every packet
        verifier = __static_crc32c_verifier

    elif isinstance(alg, ValidationAlg_RsaSha256):
        try:
            rsa_pub_key = keystore.get_rsa(alg.keyid())
        except KeyIdNotFoundError:
            print(f'Signature not validated, could not find RSA key in keystore with keyid {alg.keyid()}')
            return

        # TODO: we should cache these
        verifier = RsaSha256Verifier(key=rsa_pub_key)
    else:
        raise ValueError(f'Validation alg {alg} not supported.')

    result = verifier.verify(packet.body().serialize(), alg.serialize(),
                             validation_payload=packet.validation_payload())
    if not result:
        raise ValueError(f'Packet fails validation')
    print(f"Packet validation success with {verifier}")
    return


def _get_aead_decryptor(keystore: InsecureKeystore, security_ctx: AeadCtx):
    try:
        params = keystore.get_aes_key(security_ctx.key_number())
    except KeyNumberNotFoundError:
        print(f'Manifest not decrypted, could not find AES key in keystore with {security_ctx.key_number()}')
        return None

    return AeadDecryptor(params)


def _get_oaep_decryptor(keystore, security_ctx):
    return RsaOaepDecryptor(keystore)


def decrypt_manifest(keystore: InsecureKeystore, manifest: Manifest) -> Manifest:
    if not manifest.is_encrypted():
        return manifest

    security_ctx = manifest.security_ctx()
    if isinstance(security_ctx, AeadCtx):
        decryptor = _get_aead_decryptor(keystore, security_ctx)
    elif isinstance(security_ctx, RsaOaepCtx):
        decryptor = _get_oaep_decryptor(keystore, security_ctx)
    else:
        print(f"Unsupported encryption mode: {security_ctx}")
        return None

    try:
        return decryptor.decrypt_manifest(manifest)
    except DecryptionError as e:
        print(f"Failed decryption: {e}")
