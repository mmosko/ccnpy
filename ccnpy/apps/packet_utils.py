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
from ccnpy.crypto.InsecureKeystore import InsecureKeystore
from ccnpy.crypto.RsaSha256 import RsaSha256Verifier
from ccnpy.flic.aeadctx.AeadDecryptor import AeadDecryptor
from ccnpy.flic.tlvs.AeadCtx import AeadCtx
from ccnpy.flic.tlvs.Manifest import Manifest

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
        except KeyError:
            raise KeyError(f'Could not find RSA key in keystore with keyid {alg.keyid()}')

        if rsa_pub_key is None:
            print(f"Packet requires RsaSha256 verifier, but no key matching keyid {alg.keyid} found.")
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

def decrypt_manifest(keystore: InsecureKeystore, manifest: Manifest) -> Manifest:
    if not manifest.is_encrypted():
        return manifest

    security_ctx = manifest.security_ctx()
    if isinstance(security_ctx, AeadCtx):
        key = keystore.get_aes_key(security_ctx.key_number())
        salt = keystore.get_aes_salt(security_ctx.key_number())
        decryptor = AeadDecryptor(key=key, key_number=security_ctx.key_number(), salt=salt)

        try:
            return decryptor.decrypt_manifest(manifest)
        except DecryptionError as e:
            print(f"Failed decryption: {e}")
    else:
        print(f"Unsupported encryption mode: {security_ctx}")
