# Pure Python CCNx 1.0

`ccnpy` is a pure python implementation of the CCNx 1.0
protocols (RFC 8609 and RFC 8569).

The implementation focuses on the client libraries used to consume or produce content and to
organize it in manifests.  There is no plan to create a python CCNx forwarder.  Currently,
the code only writes packets, in wire format, to files or reads them from files; there are
no network operations.

The primary use of this code, at the moment, is to prototype the FLIC Manifest specification.   Everything is
still in play at the moment and this is not a final specification or implementation yet.

This project uses `poetry` for the python build system.

Table Of Contents:
* [Application Interface](#Application-Interface)
* [Programming Interfaces](#Programming-Interfaces)
* [Command-line Examples](#Examples)
* [FLIC Manifests](#FLIC-Manifests)
* [Implementation Notes and dependencies](#Implementation-Notes)

# Usage
## Application Interface

* ccnpy.apps.manifest_writer: slice up a file into nameless data content objects and organize them into a manifest tree.
    The output packets are written to a file system directory.
* ccnpy.apps.packet_reader: reads a packet from the file system and decodes it.  Still a little messy on the display.
* ccnpy.apps.manifest_reader: given a manifest name, assembles the application data and writes it to a file. (IN PROGRESS)

## Programming Interfaces

* ccnpy.core: This package has the main CCNx objects.
* ccnpy.flic: The FLIC objects for manifests
* ccnpy.flic.tree: Tree building and related classes.
* ccnpy.flic.presharedkey: The preshared key encryptor/decryptor for manifests
* ccnpy.crypto: Crypto algorithms for AES and RSA.  Used by encryptor/decryptor and ccnpy signers and verifiers.

## Three CCNx Modes

As per the FLIC specification, Sec 3.9.1, there are three main ways that CCNx
can use FLIC: Hash Schema, Single Prefix schema, and Segmented Schema.  We do not repeat
all the text from the specification, but only give an overview of the usage.

### Hash Schema

In this mode, there is one CCNx name associated with the root manifest and
a CCNx locator used to fetch the nameless objects (top manifest, internal manifests, and
data objects).  The manifests may use one locator and the data objects could use
a second locator.  For example, the nameless object manifests could be stored
under `ccnx:/foo` and the data stored under `ccnx:/bar`.

```bash
manifest_writer --schema HashSchema --name RN [--manifest-locator ML] [--data-locator DL] ...
```

Nameless objects require a locator.  The default is to use `RN` as the locator for all
nameless objects.  If `ML` is given, then `ML` is used as the manifest locator instead of `RN`.  If `DL` is
given, then `DL` is used for the data locator instead of `RN`.

Specifying `ML` or `DL` causes manifest and data to use separate hash groups.

### Single Prefix Schema

In this mode, there is a single CCNx name used for all manifests and data.  They are differentiated
only by the ContentObjectHash.

If only `name` is given, it is used for all manifests and data.  The `name` is always used
for the root manifest name.  In this case, there is only one hash group, and it has a single
locator of `name`.

If `MP` is given, it is the common name for all non-root manifests.  There will be two hash groups, as
al data objects will use `name` as their locator.

If 'DP' is given, it is the common name for all data objects.


```bash
manifest_writer --schema PrefixSchema --name N --manifest-prefix MP --data-prefix DP ...
```

### Segmented Schema

In this mode, one name is used for the manifest tree and another name is used for the data tree.
Every name has a ChunkNumber.  Each GroupData has a StartSegmentId in it to help with the numbering
of chunks.  The root manifest has a unique name.  There are always two name spaces for
Segmented Schema.

No locators are used, as all objects have their own name.  (For an NDN implementation, this
could be different)

The Root Manifest contains the NsDefs for the name constructors.  These contain the node locators.

```bash
manifest_writer --schema SegmentedSchema --name N --manifest-prefix MP --data-prefix DP  ...
```

The manifest prefix must be different from the data prefix.  FLIC will append chunk numbers to each of the names.

TThe root manifest will be named simply 'N'.  The internal manifest nodes (and top node) will use
chunked names of prefix 'MP'.  MP may be the same as N, in which case the root name is unchunked and
the internal names are chunked.  Likewise, 'DP' prefix could be the same as 'N', as long as 'MP' is distinct
from 'DP'.

## Encryption

A manifest tree and its data are unencrypted unless otherwise specified.  The FLIC specification has an AES encrypted
mode.  The AES keys can either be referenced in a security context or can be encrypted under RSA-OAEP and wrapped
inside the manifest.

The `manifest_writer` utility does not support separate manifest and data encryption.  If the user specifies
encryption on the command line, manifests and data are encrypted under the given AES key.

## Examples

TBD: These need to be re-factored based on the 3 usages above.

In this example, we will use `ccnpy.apps.manifest_writer` to split a file into namesless content objects
and construct a manifest tree around them.  First, we look at the command-line for `manifest-writer`.  See below
for background on [CCNx FLIC manifets](#FLIC-Manifests)

You may need to run `poetry build` and `poetry install` before `poetry run`.

```text
ccnpy$ poetry run manifest_writer --help
usage: manifest_writer [-h] [--schema {Hashed,Prefix,Segmented}] --name NAME [--manifest-locator MANIFEST_LOCATOR] [--data-locator DATA_LOCATOR] [--manifest-prefix MANIFEST_PREFIX] [--data-prefix DATA_PREFIX] [-d TREE_DEGREE]
                       [-k KEY_FILE] [-p KEY_PASS] [--wrap-key WRAP_KEY] [--wrap-pass WRAP_PASS] [--enc-key ENC_KEY] [--aes-mode {GCM,CCM}] [--key-num KEY_NUM] [--salt SALT] [--kdf {HKDF-SHA256,HKDF-SHA384,HKDF-SHA512}]
                       [--kdf-info KDF_INFO] [--kdf-uuid | --no-kdf-uuid] [--kdf-salt KDF_SALT] [-s MAX_SIZE] [-o OUT_DIR] [--link] [-T] [--root-expiry ROOT_EXPIRY] [--node-expiry NODE_EXPIRY] [--data-expiry DATA_EXPIRY]
                       filename

positional arguments:
  filename              The filename to split into the manifest

options:
  -h, --help            show this help message and exit
  --schema {Hashed,Prefix,Segmented}
                        Name constructor schema (default Hashed)
  --name NAME           CCNx URI for root manifest
  --manifest-locator MANIFEST_LOCATOR
                        CCNx URI for manifest locator
  --data-locator DATA_LOCATOR
                        CCNx URI for data locator
  --manifest-prefix MANIFEST_PREFIX
                        CCNx URI for manifests (Segmented only)
  --data-prefix DATA_PREFIX
                        CCNx URI for data (Segmented only)
  -d TREE_DEGREE        manifest tree degree (default is max that fits in a packet)
  -k KEY_FILE           RSA key in PEM format to sign the root manifest
  -p KEY_PASS           RSA key password (otherwise will prompt)
  --wrap-key WRAP_KEY   Wrapping key for RSA-OAEP mode.
  --wrap-pass WRAP_PASS
                        Wrapping key key password (otherwise will prompt).
  --enc-key ENC_KEY     AES encryption key (hex string)
  --aes-mode {GCM,CCM}  Encryption algorithm, default GCM
  --key-num KEY_NUM     Key number of pre-shared key (defaults to key hash)
  --salt SALT           Upto a 4-byte salt to include in the IV with the nonce.
  --kdf {HKDF-SHA256,HKDF-SHA384,HKDF-SHA512}
                        Use a KDF
  --kdf-info KDF_INFO   KDF INFO string (ascii or 0x hex string)
  --kdf-uuid, --no-kdf-uuid
                        Use a Type 1 UUID for the KdfInfo (overrides --kdf-info)
  --kdf-salt KDF_SALT   Upto a 4-byte salt to include in the KDF function.
  -s MAX_SIZE           maximum content object size (default 1500)
  -o OUT_DIR            output directory (default='.')
  --link                When writing to a directory, write links for named objects
  -T                    Use TCP to 127.0.0.1:9896
  --root-expiry ROOT_EXPIRY
                        Expiry time (ISO format, .e.g 2020-12-31T23:59:59+00:00) to expire root manifest
  --node-expiry NODE_EXPIRY
                        Expiry time (ISO format) to expire node manifests
  --data-expiry DATA_EXPIRY
                        Expiry time (ISO format) to expire data nameless objects
```
 
The default behavior is to write the wire format packets to a directory.  With the `-T` option, it will write them
to the standard CCNx port.

### Preferred Usage

If you have a shared symmetric key, you can directly encrypt with that key.  You should use a KDF with
a KDF info for the manifest tree.  You can generate a unique KDF info several ways: (1) specify `--kdf-uuid`,
(2) leave the `--kdf-info` blank and use segmented schema so all objects have a unique name, or (3)
externally generate a unique ID for the manfiest tree and put it in the `--kdf-info`.  Because the `--key-number`
is included in the KDF FixedInfo, the `--kdf-info` really only needs to be unique per key number.

Example:
```bash
ccnpy$ poetry run manifest_writer \
   --schema Hashed \
   --name ccnx:/foo.com/object \
   --link \
   -k test_key.pem -p '' \
   --enc-key 0102030405060708090a0b0c0d0e0f10 --salt 0x01020304 --key-num 1 --aes-mode CCM \
   --kdf hkdf-sha256 --kdf-uuid \
   -s 500 \
   -o output \
   filename
```

If you have a shared key encryption key, where the publisher has the public key and the consumer(s) have
the private key, then you can use the RSA-OAEP mode.  The key encryption key must be at least 1024 bits long.
This method can generate a unique encryption key per manifest tree, so you do not need to include `--kdf-info`.
It is still recommended to use a kdf.  

In RSA-OAEP mode, the root manifest will include an RSA encryption of the RSA key size (e.g. 128 bytes for a 1024-bit key, 
or 512 bytes for a 4096-bit key, etc.).  With an RSA signature and other data, the root manifest may be approximately
1400 bytes with a 4096-bit wrapping key and 4096-bit signing key and a short name.

Example:
```bash
ccnpy$ poetry run manifest_writer \
   --schema Hashed \
   --name ccnx:/foo.com/object \
   --link \
   -k test_key.pem -p '' \
   --wrap-key `shared_key.pub` --wrap-pass '' \
   --kdf hkdf-sha256 \
   -s 500 \
   -o output \
   filename
```

### Small Packet Example

We create an RSA key that will be used to sign the root manifest, create a temporary
output directory, and then run `manifest_writer`.  We limit the tree to node degree 11
and a maximum packet size of 500 bytes.  Using at 1500 byte packet will allow a tree degree
of 41.  Internally, `ccnpy.flic.tree.TreeOptimizer` calculates the best tradeoff between
direct and indirect pointers per internal manifest node to minimize the waste in the tree,
so you do not need to specify the exact fanout.
    
```bash
ccnpy$ openssl genrsa -out test_key.pem
ccnpy$ openssl rsa -pubout -in test_key.pem -out test_key.pub
ccnpy$ mkdir output
ccnpy$ poetry run manifest_writer \
   --schema Hashed \
   --name ccnx:/foo.com/object \
   --link \
   -k test_key.pem -p '' \
   --enc-key 0102030405060708090a0b0c0d0e0f10 --salt 0x01020304 --key-num 1 --aes-mode CCM \
   -s 500 \
   -o output9 \
   LICENSE
Namespace(schema='Hashed', name='ccnx:/foo.com/object', manifest_locator=None, data_locator=None, 
  manifest_prefix=None, data_prefix=None, tree_degree=None, key_file='test_key.pem', key_pass='', 
  wrap_key=None, wrap_pass=None, enc_key=b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10', 
  aes_mode='CCM', key_num=KeyNum (1), salt=16909060, kdf_alg=None, kdf_info=None, kdf_uuid=False, 
  kdf_salt=None, max_size=500, out_dir='output9', write_links=True, use_tcp=False, root_expiry=None, 
  node_expiry=None, data_expiry=None, filename='LICENSE')
Creating manifest tree
Root manifest hash: HashValue: {alg: 'SHA256', val: '72948d88ecc64b528c8d76db86e26b147db23dc485313bd09a2c08ae01a4b5e8'}
````

First, let us go over the command-line term by term:
- `--schema` specifies the Hashed schema, so only the root manifest will have a name.
- `--name` is the name of the root manifest.
- `--link` is useful for writing objects to a direct.  It creates a link from the name to the object hash, 
   so `manifest_reader` can find the root object without typing in the hash value.
- `-k` and '-p' open up a PEM private key file to use for signing the root manifest.  Using "-p ''" uses a blank 
  password for the PEM file.  If -p is not specified, `manifest_writer` will prompt for a password.
- The AEAD parameters are `--enc-key` and `--salt` and `--key-num` and `--aes-mode`.  The first specifies
  the encryption key as a hex string (16 bytes or 32 bytes).  The salt is an optional 4-byte value (as an int or hex string) to use
  with the nonce to create an IV.  The key number identifies the key to the consumer.  The AES mode can
  be either GCM or CCM.
- `-s` limits the maximum packet size to 500 bytes.  We picked a smaller value to illustrate multiple
  packets.  1500 or 1492 or 1480 are more common values.
- `-o` is the output directory to write the wire-format objects.  There is a `-T` option to use the network.
- `LICENSE` is the filename to chunk up and wrap in a manifest.

The text output lines are:
- `Namespace` is all the CLI arguments (the work `Namespace` is from the python argument parser).
- `Root manifest hash...` is the SHA256 hash of the root manifest object, which we will use shortly.

Looking at the output directory, we see that all the CCNx Packets are 500 bytes or less, which is exactly what
we asked for.  The ones exactly 500 bytes are the data content objects.  The others are manifests, which do not
exactly fit in 500 bytes.  The various sizes depend on the number of pointers in each one.  We will look at
packet dumps below.

```bash
ccnpy$ ls -lgo output
-rw-r--r--@ 1   500 Nov 10 11:51 0c48afc336dfbc04aae31b1c20f159c53ba5d212160ae48015358bcfe1d223fd
-rw-r--r--@ 1   500 Nov 10 11:51 0f5043db4c988440d9803c71e6d4daf47867cdba56e182ccc2e830231a8178fb
-rw-r--r--@ 1   500 Nov 10 11:51 125fae41a28989145d34ab188fe2190caa4b97011e69446dfe49f5232d609b3b
-rw-r--r--@ 1   500 Nov 10 11:51 166fc57cad5de9584c3ebdac85a1db968ae41b2d59112ac4818ac3242bf2ff4a
-rw-r--r--@ 1   500 Nov 10 11:51 1da52e06097ebf55200640b24e065976943d661133bbe7376801e10f45c2d1f4
-rw-r--r--@ 1   324 Nov 10 11:51 249b13c4a21062eaba0e2a4e1170b6f7a3a003d260b6fcab3566d4c82cd5cb10
-rw-r--r--@ 1   361 Nov 10 11:51 28df0ce6953593d4f869a0a1a45682c52752303329628daf7263dcc3fa8afa4d
-rw-r--r--@ 1   500 Nov 10 11:51 2b293564ccc0ba4f8f85e8e5a4ef90bb58c429a7a0b388a441b086488a288427
-rw-r--r--@ 1   500 Nov 10 11:51 31065331e00e3eb32fee93c9f2f6339e788d041c32bd242444892c6249e08e90
-rw-r--r--@ 1   500 Nov 10 11:51 4d2f184d12c10e103898277348a756e1c5bdb592eeb6e2f12cd0dcceed905bac
-rw-r--r--@ 1   500 Nov 10 11:51 64d8aaebd9f402b833d4c3c64b0b4fed40101f3388a1fa1e0d8eedef4ae23617
-rw-r--r--@ 1   500 Nov 10 11:51 6698535f4847008068589a117bdb410c17d8d04bf6b91ba5bfcbd43ec49e5f5e
-rw-r--r--@ 1   500 Nov 10 11:51 67cbb9b8b5ddee8d98311bbcdb792c0adc14171785aca5b1777dd8b2b4a70ed8
-rw-r--r--@ 1   500 Nov 10 11:51 6d0e16c90c3d8188f7befdd8ce1e72c21d225cc0b52439d3411a4f51b09b5aed
-rw-r--r--@ 1   468 Nov 10 11:51 6db7a2edef022949ad96e58945930ed7ceb4593d1b23dffee90a018154cefd42
-rw-r--r--@ 1   343 Nov 10 11:51 72948d88ecc64b528c8d76db86e26b147db23dc485313bd09a2c08ae01a4b5e8
-rw-r--r--@ 1   500 Nov 10 11:51 83ae6c02983fc75e0eb756d8b6780f3b8ac54bfe46f2886013ea1ec8262a517f
-rw-r--r--@ 1   500 Nov 10 11:51 887335c9ad28820c8c7ea6fdc1a958161e3c853c246038a90787876843cc4f5d
-rw-r--r--@ 1   500 Nov 10 11:51 af182acb54e102a5dd1ea4e944a2b0bc04d89aaac5b7d22d860a9cc970d88185
-rw-r--r--@ 1   500 Nov 10 11:51 b2180a827443e3329fe3863656312ccf1978d212b49975e41499f908d39b9704
-rw-r--r--@ 1   500 Nov 10 11:51 d246d972b2fe993556041a27d1244a3fe3122105927aaed587448083247d9d4a
-rw-r--r--@ 1   500 Nov 10 11:51 d7bc2a27eb1c1bf08c31f1de582f7c49acccddee141058ccac5a41988f7d4a6c
-rw-r--r--@ 1   500 Nov 10 11:51 d9a71da31961aa48e32e5a6b0b3784204984cd1e5a4471226bcd6a32f42c4fe8
-rw-r--r--@ 1   500 Nov 10 11:51 dfd5474165928f5c87717674fb5f76cf39241a9ea8842ea009870827890dfc59
-rw-r--r--@ 1   500 Nov 10 11:51 e3df9814e3f6e030fa90d512b519693f9d87a1e1f893efe4e3a7c2238e966527
-rw-r--r--@ 1   500 Nov 10 11:51 e6743bcfb3fbb12daa2bc9f4bbad14e8ec620e82c6b929506167bd324ecaa9f1
-rw-r--r--@ 1   468 Nov 10 11:51 e8230daf3502a6e120300d1e9d3565769f34026a65023a9ab85b5e421ab593f3
-rw-r--r--@ 1   500 Nov 10 11:51 f68375a22c5654f1f180c12dc040e8a94cc7aae5edaebfd7ab02a3a92094a47d
-rw-r--r--@ 1   239 Nov 10 11:51 link_0000001500010007666f6f2e636f6d000100066f626a656374
```

One special file is `link_0000001500010007666f6f2e636f6d000100066f626a656374`.  It was generated
by the `--link` CLI option.  In this first packet decode, we see it is a Content Object that
has a payload type of LINK.  The payload is a Link TLV with the name `ccnx:/foo.com/object` and
a hash restriction of `72948d88ecc64b528c8d76db86e26b147db23dc485313bd09a2c08ae01a4b5e8`.
That is the same hash of the root manifest written out above by `manifest_writer`.
We will see how it is used in just a bit below.

Note in the validation algorithm, we have an RSA SHA256 signature, which is validated by `test_key.pub`.
The hash shown in the `RsaSha256Verifier` is the public key ID.  You can verify this on the CLI with:
```openssl rsa -pubin -in test_key.pub -outform DER | openssl sha256```.

```bash
poetry run packet_reader \
                --pretty \
                -i output \
                -k test_key.pub \
                link_0000001500010007666f6f2e636f6d000100066f626a656374
{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 239,
         flds: '000000',
         hlen: 8
      },
      CO: {
         NAME: [Name = b 'foo.com', Name = b 'object'],
         None,
         PLDTYP: 'LINK',
         Link(NAME: [Name = b 'foo.com', Name = b 'object'], None, HashValue: {
            alg: 'SHA256',
            val: '72948d88ecc64b528c8d76db86e26b147db23dc485313bd09a2c08ae01a4b5e8'
         }),
         None
      },
      RsaSha256: {
         keyid: HashValue: {
            alg: 'SHA256',
            val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'
         },
         pk: None,
         keylink: None,
         'SignatureTime': '2024-11-10T19:51:45.477000+00:00'
      },
      ValPld: 'cbd2478893b2019918d3eb0ba03ad4a343dc68e00bdb564a1069f3ce7515ecaedb60946bea9edf5c78ae3556700de107f016827e6e17106fee08899b1d56273e'
   }
}

Packet validation success with RsaSha256Verifier(HashValue: {alg: 'SHA256', val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'})
```

We can look into each of these packets.  First, look at the root manifest, whose hash-based name was in the
output of `manifest_writer`.  `packet_reader` can use either a private key or public key to verify the
signature on a CCNx packet.  We show the usage with a public key, but the syntax is the same for a private key.
Note that after displaying the content object, it shows "Packet validation success..." before the decrypted packet.

The CLI arguments for `packet_reader` are largely the same as `manifest_writer`.  The difference is `--pretty` controls
if a verbose structured output is used, or a more compact format otherwise.  The filename is what to read, not what
to encode.  In this example, we use the root manfiest content object hash, as that is the filename in
the output directory we want to read.  

If the AES encryption parametes are not given, `packet_reader` will only
display the ContentObject, but cannot decode the embedded manifest.  We see in the `Packet {...}` section, the 
Content Object `CO {...}` has a payload type of "MANIFEST" and it shows what it can.  In this case, the manifest
is encrypted so it can only show the preshared key information, the encrypted node bytes, and the AEAD 
authentication tag.  Note that the nonce is only 8 bytes, not 12, because we added a 4-byte salt.

```bash
ccnpy$ poetry run packet_reader \
  --pretty \                
  -i output \
  --enc-key 0102030405060708090a0b0c0d0e0f10 --salt 0x01020304 --key-num 1 --aes-mode CCM \
  -k test_key.pub \
  72948d88ecc64b528c8d76db86e26b147db23dc485313bd09a2c08ae01a4b5e8
  
AeadImpl: (num: 1, salt: b'\x01\x02\x03\x04', mode: CCM, key len: 128)
{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 343,
         flds: '000000',
         hlen: 8
      },
      CO: {
         NAME: [Name = b 'foo.com', Name = b 'object'],
         None,
         PLDTYP: 'MANIFEST',
         Manifest: {
            PSK: {
               kn: 1,
               iv: 'fb12ad1400d2c6a9',
               mode: 'AES-CCM-128'
            },
            EncNode: 'b7b44763e6b670743d4dfc03e471555141af4da4ca28254d349b2ef879a0ccc9080d6627ea7ebd87220e283ef0b826f4c1f79a6f71ea73cfe62c26bbf6bca7413aba1fe1a721ef4bd201a702264f0929d364e97d5e916e3293ccc701ee1c488cf31c81372a9346f856b7ec2c66bae782096006',
            AuthTag: '0a1ba6ab91530089c42cbbea52858fd8'
         },
         None
      },
      RsaSha256: {
         keyid: HashValue: {
            alg: 'SHA256',
            val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'
         },
         pk: None,
         keylink: None,
         'SignatureTime': '2024-11-10T19:51:45.474000+00:00'
      },
      ValPld: 'be6eb21a8c37af22bfed341aa81fdd4a02e4d6d03c4bc6b91d76ca40f247c56b879b6d5e88c56637888c66983e569fdf1e3b6f3876051a9592e842b4e8574f00'
   }
}

Packet validation success with RsaSha256Verifier(HashValue: {alg: 'SHA256', val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'})
AeadImpl: (num: 1, salt: b'\x01\x02\x03\x04', mode: CCM, key len: 128)
Manifest: {
   None,
   Node: {
      NodeData: {
         SubtreeSize: 11357,
         None,
         None,
         [NCDEF: (NCID: 1, HS: Locators: [Locator: Link(NAME: [Name =
            b 'foo.com', Name = b 'object'
         ], None, None)], None)],
         None
      },
      1,
      [HashGroup: {
         GroupData: {
            None,
            None,
            None,
            None,
            NCID: 1,
            None
         },
         Ptrs: [HashValue: {
            alg: 'SHA256',
            val: 'e8230daf3502a6e120300d1e9d3565769f34026a65023a9ab85b5e421ab593f3'
         }]
      }]
   },
   None
}
```

Because we provided the correct decryption key and key number on the command-line, `PacketReader` also decrypted
the manifest.  This shows there is a Node with NodeData and a subtree size of 11,357 bytes (the file size of LICENSE).
There is 1 HashGroup with one pointer, as is normal for the named and signed root manifest.  The hash group
uses NCID 1, which was defined in the NodeData.

The `NodeData` has one name constructor definition, with a locator of `ccnx:/example.com/manifest`.  That is the same
name as the root manifest, as we only provided the `--name` flag.  See below for an example with
the `--manifest-locator` and `--data-locator` flags.

Using the root manifest pointer, the next manifest decodes as below.  This is a nameless content object: there is no name and there is no validation,
we only refer to it by its hash name.  The decryption shows that the manifest has 10 hash pointers, which is less
than we limited the tree to (it was 11 to `manifest_writer`).  Most of those are direct data pointers and the last few 
will be indirect manifest  pointers.  A quick scan of the file list above shows that the `1da...` file is the 
last in the list to be exactly 500 bytes, so there are 8 direct pointers and 2 indirect pointers (indirect pointers
are always last due to the post order traversal).

```bash
ccnpy$ poetry run packet_reader \
  --pretty \                
  -i output \
  --enc-key 0102030405060708090a0b0c0d0e0f10 --salt 0x01020304 --key-num 1 --aes-mode CCM \
  -k test_key.pub \
  e8230daf3502a6e120300d1e9d3565769f34026a65023a9ab85b5e421ab593f3
AeadImpl: (num: 1, salt: b'\x01\x02\x03\x04', mode: CCM, key len: 128)
{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 468,
         flds: '000000',
         hlen: 8
      },
      CO: {
         None,
         None,
         PLDTYP: 'MANIFEST',
         Manifest: {
            PSK: {
               kn: 1,
               iv: '321d47ac0fd0284c',
               mode: 'AES-CCM-128'
            },
            EncNode: 'a05ee07e5ca3b1dc4900f85db61e33a844079e8aa4eb8ba6ee11a53e0b48cc9c5953d2832a4678bdfd844c2cca511718909774aa1fdc110cd46e645dc97dde2cfe34b3a7bc66ecfc62c5f560d49b354820367c1c8ffc10ccb8e3a7343e6f472952c256b099b1e77d07ed9e6d46cd61bfda42f34e9663d94f302388459d6388eaca2e906a8d4750d00b18f2bd5eda863c8e385ab0e6183fb54c7323531fa07e05642f2eb96b2157aa9cd739c7ee7f5386e2711c8e73a084f5c6456b08b0c05fd71609a102c5745b80a0c2e0f98f2e99a3f2e08d93566273d678d8dea4398bb85dac356badba6f5be9a5561c55ffdbd7fb832a02446ca9d21694bbaf871b83f8cf1ae9be9fbe2d79d3715079264bca49e911273bac31bcfd32af75d30c516b8429580b6ebba20e866b86ab7f44250ca63954c0faae3f035c88cbddbc2d3ef8f9a63f0c38c57f5af6bba0c7047ba6cca5d460b01c077090ee8e8a5041d2ede8982e2ee3f14fda25627bb693815cd4da125aa83ffbf8b31d1dc861cb7f24e70e96eeb94b9e8c141fa3659d',
            AuthTag: 'ee905d3a8c427763f06d3820df55662c'
         },
         None
      },
      None,
      None
   }
}

AeadImpl: (num: 1, salt: b'\x01\x02\x03\x04', mode: CCM, key len: 128)
Manifest: {
   None,
   Node: {
      NodeData: {
         SubtreeSize: 11357,
         None,
         None,
         [],
         None
      },
      10,
      [HashGroup: {
         GroupData: {
            None,
            None,
            None,
            None,
            NCID: 1,
            None
         },
         Ptrs: [HashValue: {
            alg: 'SHA256',
            val: '31065331e00e3eb32fee93c9f2f6339e788d041c32bd242444892c6249e08e90'
         }, HashValue: {
            alg: 'SHA256',
            val: 'e6743bcfb3fbb12daa2bc9f4bbad14e8ec620e82c6b929506167bd324ecaa9f1'
         }, HashValue: {
            alg: 'SHA256',
            val: 'af182acb54e102a5dd1ea4e944a2b0bc04d89aaac5b7d22d860a9cc970d88185'
         }, HashValue: {
            alg: 'SHA256',
            val: '887335c9ad28820c8c7ea6fdc1a958161e3c853c246038a90787876843cc4f5d'
         }, HashValue: {
            alg: 'SHA256',
            val: 'e3df9814e3f6e030fa90d512b519693f9d87a1e1f893efe4e3a7c2238e966527'
         }, HashValue: {
            alg: 'SHA256',
            val: '4d2f184d12c10e103898277348a756e1c5bdb592eeb6e2f12cd0dcceed905bac'
         }, HashValue: {
            alg: 'SHA256',
            val: '83ae6c02983fc75e0eb756d8b6780f3b8ac54bfe46f2886013ea1ec8262a517f'
         }, HashValue: {
            alg: 'SHA256',
            val: '1da52e06097ebf55200640b24e065976943d661133bbe7376801e10f45c2d1f4'
         }, HashValue: {
            alg: 'SHA256',
            val: '249b13c4a21062eaba0e2a4e1170b6f7a3a003d260b6fcab3566d4c82cd5cb10'
         }, HashValue: {
            alg: 'SHA256',
            val: '6db7a2edef022949ad96e58945930ed7ceb4593d1b23dffee90a018154cefd42'
         }]
      }]
   },
   None
}
```

The `--link` option is useful if you will use `manifest_reader` on the directory.  In that case, it can
quickly find the root manifest by name alone rather than have to search for it.

The link filename is always of the form `link_{serialized_name}`, where `serialized_name` is the
hex encoding of the Name TLV.  In the example below, this parses as:

```text
0000 0015      ; Name TLV (type = 0, length = 21)
0001 0007      ; Name Component TLV (type = 1, length = 7)
666f6f2e636f6d ; hex for 'foo.com'
0001 0006      ; Name Component TLV (type = 1, length = 7)
6f626a656374   ; hex for 'object'
```

```bash
ccnpy$ poetry run packet_reader -i output --pretty -k test_key.pem -p '' link_0000001500010007666f6f2e636f6d000100066f626a656374
{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 239,
         flds: '000000',
         hlen: 8
      },
      CO: {
         NAME: [Name = b 'foo.com', Name = b 'object'],
         None,
         PLDTYP: 'LINK',
         Link(NAME: [Name = b 'foo.com', Name = b 'object'], None, HashValue: {
            alg: 'SHA256',
            val: '72948d88ecc64b528c8d76db86e26b147db23dc485313bd09a2c08ae01a4b5e8'
         }),
         None
      },
      RsaSha256: {
         keyid: HashValue: {
            alg: 'SHA256',
            val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'
         },
         pk: None,
         keylink: None,
         'SignatureTime': '2024-11-10T19:51:45.477000+00:00'
      },
      ValPld: 'cbd2478893b2019918d3eb0ba03ad4a343dc68e00bdb564a1069f3ce7515ecaedb60946bea9edf5c78ae3556700de107f016827e6e17106fee08899b1d56273e'
   }
}

Packet validation success with RsaSha256Verifier(HashValue: {alg: 'SHA256', val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'})
```

With the pre-shared key (AeadCtx) encryptioh mode, we can also specify that it should use a KDF
and a byte string that is used in the FixedInfo.  With the CLI shown below, the AES CCM encryption
will use a derived key from HKDF-SHA256 with a FixedInfo build from the byte string '0x57377849'
and an HKDF salt of '0x999999'.  See the FLIC RFC for details on how FixedInfo is calculated.

```bash
ccnpy$ mkdir output10
ccnpy$ poetry run manifest_writer    \
  --schema Hashed \
  --name ccnx:/foo.com/object \
  --link \
  -k test_key.pem -p '' \
  --enc-key 0102030405060708090a0b0c0d0e0f10 --salt 0x01020304 --key-num 1 --aes-mode CCM \
  --kdf hkdf-sha256 --kdf-info 0x57377849 --kdf-salt 0x999999 \
  -s 500 \
  -o output10 \
  LICENSE
Namespace(schema='Hashed', name='ccnx:/foo.com/object', manifest_locator=None, data_locator=None, manifest_prefix=None, data_prefix=None, tree_degree=None, key_file='test_key.pem', key_pass='', wrap_key=None, wrap_pass=None, enc_key=b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10', aes_mode='CCM', key_num=KeyNum (1), salt=16909060, kdf_alg=HKDF-SHA256, kdf_info=KdfInfo: '0x57377849', kdf_uuid=False, kdf_salt=10066329, max_size=500, out_dir='output10', write_links=True, use_tcp=False, root_expiry=None, node_expiry=None, data_expiry=None, filename='LICENSE')
Creating manifest tree
Root manifest hash: HashValue: {alg: 'SHA256', val: '0x5f0063b2d03e057c2dafe703fc824c319d6cd0ecee2a9cb4d1e0a25221bc4add'}
```

One of the encrypted manifests looks like this.  We see that the AeadData now contains a KDF.  Then encypted manifests
will use a derived key.

```bash
ccnpy$ poetry run packet_reader -i output10 --pretty 5f0063b2d03e057c2dafe703fc824c319d6cd0ecee2a9cb4d1e0a25221bc4add
{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 354,
         flds: '0x000000',
         hlen: 8
      },
      CO: {
         NAME: [Name = b 'foo.com', Name = b 'object'],
         None,
         PLDTYP: 'MANIFEST',
         Manifest: {
            PSK: {
               AeadData: {
                  KeyNum(1),
                  Nonce: {
                     '0xcefc4e7554130729'
                  },
                  AeadMode(3): 'AES-CCM-128',
                  KdfData: {
                     KdfAlg(1),
                     KdfInfo: '0x57377849'
                  }
               }
            },
            EncNode: '0x029e772e6defe77aea4ead71feeaa41a87b89c1a2707a947cb2e96256359c4be31ba6d41b50174a5d5c03bd0c4b7af8a96e60fd1f7c67ffb6814dcbdec532981c8593b7fd8a6bb6f53e48507db73191d78b069fcc1f25c73cf4b87a907fdfd8c24c0c29b80ac3ab3fff765a1f0',
            AuthTag: '0x2fbac34b78b7230116590c35dcaa24a2'
         },
         None
      },
      RsaSha256: {
         keyid: HashValue: {
            alg: 'SHA256',
            val: '0xc94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'
         },
         pk: None,
         keylink: None,
         'SignatureTime': '2024-11-30T04:21:24.071000+00:00'
      },
      ValPld: '0x75d5345a92ea5c5d542cacb2dbdcc793fcb85269d6ec9c9ef23113eafe96f16ce4ae3bfce3f0233957f74591f4da096cd485e4714374b94bb36ad167a7fffb2f'
   }
}
Signature not validated, could not find RSA key in keystore with keyid HashValue: {alg: 'SHA256', val: '0xc94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'}
Manifest not decrypted, could not find AES key in keystore with KeyNum (1)
None
````


Another encryption technique is to use RSA-OAEP key wrapping rather than sharing a symmetric key.
In this mode, the publisher uses an RSA public key to encrypt a symmetric key, and a consumer uses
an RSA private key to get the symmetric key.  In some cases, it may be possible to use a key distribution
system for group keying.  In this case, we specify to use a KDF, but do not include a `--kdf-info` or `--kdf-uuid`
because the symmetric key is unique to this manifest tree and it uses a random key number (which is part
of the FixedInfo of the KDF).

```bash
ccnpy$ openssl genrsa -out shared_key.pem 1024
ccnpy$ openssl rsa -pubout -in shared_key.pem -out shared_key.pub
ccnpy$ mkdir output11
ccnpy$ poetry run manifest_writer    \
  --schema Hashed \
  --name ccnx:/foo.com/object \
  --link \
  -k test_key.pem -p '' \
  --wrap-key shared_key.pub --wrap-pass '' \
  --kdf hkdf-sha256 \
  -s 500 \
  -o output11 \
  LICENSE
Namespace(schema='Hashed', name='ccnx:/foo.com/object', manifest_locator=None, data_locator=None, manifest_prefix=None, data_prefix=None, tree_degree=None, key_file='test_key.pem', key_pass='', wrap_key='shared_key.pem', wrap_pass='', enc_key=None, aes_mode='GCM', key_num=None, salt=None, kdf_alg=HKDF-SHA256, kdf_info=None, kdf_uuid=True, kdf_salt=None, max_size=500, out_dir='output11', write_links=True, use_tcp=False, root_expiry=None, node_expiry=None, data_expiry=None, filename='LICENSE')
Creating manifest tree
The root manifest packet is 542 bytes, greater than max_packet_size 500
Root manifest hash: HashValue: {alg: 'SHA256', val: '0xbf80fa3d655a29641792bacb45e24974e8b50f2136dc38be25dac86a6b4652c6'}
```

A dump of the root manifest shows and RsaOaepCtx with a KDF specified.  

```bash
$ poetry run packet_reader \
   -k test_key.pem -p '' \
   --wrap-key shared_key.pem --wrap-pass '' \
   -i output11 --pretty bf80fa3d655a29641792bacb45e24974e8b50f2136dc38be25dac86a6b4652c6
{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 526,
         flds: '0x000000',
         hlen: 8
      },
      CO: {
         NAME: [Name = b 'foo.com', Name = b 'object'],
         None,
         PLDTYP: 'MANIFEST',
         Manifest: {
            RsaOaepCtx: {
               aead: AeadData: {
                  KeyNum(2892058647),
                  Nonce('0x91072e529ece9afd'),
                  AeadMode(2): 'AES-GCM-256',
                  KdfData: {
                     KdfAlg(1),
                     None
                  }
               },
               wrapper: {
                  KeyId(HashValue: {
                     alg: 'SHA256',
                     val: '0x1b73a58d83c7f3b73ffe3fb48c0492559816a37211a86b8cb7dcb569b3cb00f4'
                  }),
                  None,
                  HashAlg(1),
                  WrappedKey: '0x0d00aeeebcf81bbd1dcfbf3745b1e26653452807de2012b3cbe185c77b16bc0b101c682971b2737a508dbf4396b884b0701565ca7149644e6c64ad6942d8e3c08f1ca86efa86f7b1e5980f13c97393a6f716f6806489d5f59f4ac7340aca55af37aca6b23ae6c4206dc60b03f05b7482f08db40d594b4d31557a35117b05f393'
               }
            },
            EncNode: '0x2d47d1c2a2774c3bb6b5a2107713f8f70122a327c5c3a920520ce10697b19ee3edb3280499e7775f08cad17e49bbec69e62020dd2afe0ef2b1b65ea1a2e5c1557575f26b2474546bbc249b09c75ced47a438b268edaf8c15a7c1541756c01a538067568baaba0ef18b8234cb9b',
            AuthTag: '0x9cc67fa4fc2cc4a94c3dcf98c9187914'
         },
         None
      },
      RsaSha256: {
         keyid: HashValue: {
            alg: 'SHA256',
            val: '0xc94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'
         },
         pk: None,
         keylink: None,
         'SignatureTime': '2024-11-30T06:29:00.501000+00:00'
      },
      ValPld: '0x9d6e591c0c7f905b8152cd519798ea2303e6b91bd509ea049ca33c9ff9183a31dccf078b60a29c31fec186ddfc834a7d8914fc2d415e216206c83fc0cb3b661f'
   }
}

Packet validation success with RsaSha256Verifier(HashValue: {alg: 'SHA256', val: '0xc94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'})
Manifest: {
   None,
   Node: {
      data = NodeData: {
         SubtreeSize: 11357,
         None,
         None,
         [NCDEF: (NCID(1), HS: Locators: [Locator: Link(NAME: [Name =
            b 'foo.com', Name = b 'object'
         ], None, None)], None)],
         None
      },
      len = 1,
      hashes = [HashGroup: {
         GroupData: {
            None,
            None,
            None,
            None,
            NCID(1),
            None
         },
         Ptrs: [HashValue: {
            alg: 'SHA256',
            val: '0x7cbad76c64fd75eb3a7d9872cb22e76abd1e8432c6454d09c8a91850bb2e5d13'
         }]
      }]
   },
   None
}
```

If you look at the top manifest (using the decoded manifest above) via:

```bash
ccnpy$ poetry run packet_reader \
  -k test_key.pem -p '' \
  --wrap-key shared_key.pem --wrap-pass '' \
  -i output11 --pretty 7cbad76c64fd75eb3a7d9872cb22e76abd1e8432c6454d09c8a91850bb2e5d13
```

you will see that the RsaOaepCtx is abbreviated without the wrapped key.  This means that `packet_reader` cannot
decrypt the manifest, because it does not have the decrypted key from the room manifest.  You would need to use
`manifest_reader` to traverse the manifests.

```text
    RsaOaepCtx: {
       aead: AeadData: {
          KeyNum(2892058647),
          Nonce('0x38be46cd0695fc76'),
          AeadMode(2): 'AES-GCM-256',
          KdfData: {
             KdfAlg(1),
             None
          }
       },
       wrapper: None
    },
```
### Using `manifest_reader`

The utility `manifest_reader` reads what `manifest_writer` produces.  In this example, we ask it to read `ccnx:/foo.com/object`, which 
is the name we used above in `manifest_writer`.  Because we include `--link`, the reader uses that to find the hash
value of the root manifest and reads that in.  It discovers the first NcDef and learns about NcId 1.  Each `NcCache` has
an instance (`inst`) identifier, because name definitions can change as we traverse a manifest.  Anytime there
is a new NcDef in the manifest tree, the reader copies the current NcCache and adds or udpates the definitions for
that branch.

The read bytes, in `flic.txt` are exactly the same as the original file `LICENSE`.

```bash
ccnpy$ run manifest_reader  \
   -i output \
   --enc-key 0102030405060708090a0b0c0d0e0f10 --salt 0x01020304 --key-num 1 --aes-mode CCM \
   -k test_key.pub \
   --name ccnx:/foo.com/object \
   --output flic.txt
Dereferenced link link_0000001500010007666f6f2e636f6d000100066f626a656374 to load packet HashValue: {alg: 'SHA256', val: '72948d88ecc64b528c8d76db86e26b147db23dc485313bd09a2c08ae01a4b5e8'}
Packet validation success with RsaSha256Verifier(HashValue: {alg: 'SHA256', val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'})
AeadImpl: (num: 1, salt: b'\x01\x02\x03\x04', mode: CCM, key len: 128)
NcCache[inst=2][ncid=1] = HS: Locators: [Locator: Link(NAME: [Name=b'foo.com', Name=b'object'], None, None)], None

Finished traversal, 28 objects procssed

ccnpy$ ls -l flic.txt LICENSE
-rwxr-xr-x@ 1 marc  staff  11357 Oct  1 20:52 LICENSE
-rw-r--r--@ 1 marc  staff  11357 Nov 10 12:28 flic.txt
ccnpy$ diff flic.txt LICENSE; echo $?
0
```

### An example using Segmented names

TBD

### Large Degree Tree

We create a 1MiB file that has all zeros and put it in a Manifest limited to 1500 byte packets.  This should
create only one or two nameless data objects, then a tree with many pointers to the same zeros.

```bash
ccnpy$ dd if=/dev/zero of=zeros bs=1000 count=1000
ccnpy$ mkdir out2
ccnpy$ poetry run manifest_writer  \
                   --name ccnx:/example.com/manifest \
                   --manifest-locator ccnx:/manifest \
                   --data-locator ccnx:/data
                   -k test_key.pem \
                   -p '' \
                   -s 1500 \
                   -o ./out2  \
                   --enc-key 0102030405060708090a0b0c0d0e0f10 \
                   --key-num 22  \
                   zeros
                   
Creating manifest tree
Root manifest hash: HashValue: {alg: 'SHA256', val: 'f74a2dd53446f597a4659d160945186b31e87f2c43f632dac54a1da033fbe147'}
```

The root manifest `f74a2...` is 490 bytes.  The main data object `81e2...` is exactly 1500 bytes.  The other
manifests mostly 1471 bytes.  The other small objects are
the remaining zeros of the file's tail (`44b8...`) and a small internal manifest without all the pointers.

```bash
ccnpy$ ls -l out2
total 176
-rw-r--r--+ 1 mmosko  1987151510  1363 Jul  1 22:32 01f57d6f3fc815352022e91d23b92bfd5c6e4a867a0c25c55eb3218440a2e37e
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 0911e9cb7115068126d2776a2d1f0b654f1a239d1df05256fc365eb4704e7d6e
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 27dcd884d48ecb54a6d6d04573484f94fcb521d7c15d2bef65f42c958020e896
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 29443f81373a91d0c750a1dcd08f5452d39a2450aa3a2ae2462a05c5787e7e49
-rw-r--r--+ 1 mmosko  1987151510   715 Jul  1 22:32 3767cd69a0e075c6bab208ff7e7d0370342028fd8ba0593c2b8c52d6539712c0
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 4298aab32d5f55d43f16caba47091038fb427cb29dafaa36c21ffad8c04849cf
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 44b7e81a2833e6a15f4b9e015a13b6eb82b44a89f2abfe4aaa120a1a28247c1e
-rw-r--r--+ 1 mmosko  1987151510   217 Jul  1 22:32 44b8f04d36f09a6295447c47c6e0501cbe83382776140e0039d7fe48d3a2c74f
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 56369e591865e4f7a9ba6a9fe2047344b83ba39505f62a8c6e8605ab4a5d51c3
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 67e1a08a586689f1e5667836a63dfa2fe8b6d8579a7ad25d085832556c7f1604
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 6aeaaf7ea24e6b0f70024591c2eff1bd7b173fe18bf9444c8beaacab7ed49dbd
-rw-r--r--+ 1 mmosko  1987151510  1363 Jul  1 22:32 7ee96456d5cf06b7f26a55b4db0a48ed52ab6a586d949d3e2e3aeca5c40a216d
-rw-r--r--+ 1 mmosko  1987151510  1500 Jul  1 22:32 81e24663be0c7c9a9e461c03392e30c7f0492fccbe0b59d41ee2913385dbf712
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 8323a0eff0a359fde41b332c19ba30f6115f687e9375bbacbe1fc5fa46a805c2
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 93a9225b2a23af8bbfea7585563d7d1dd6fcc0b9588bdc28628431fb577cd5fc
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 9c87210a9adfd49bbf985e1169e7c7797d2e753a34e95ed5260ef6fadee74954
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 a394b694fb5bc5ca90039cc46f45ccc850d943edca48ed7f14086eb84394a69e
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 b9b55f1b4ddd4bd92176b05da187cec5db37b491df1a6bac09a18b6a00a02a70
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 bde2ff654795cbb58757b4ef5b2ea384246904cf8463be685a2638afee0bcc33
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 c4911a0e6b3a11bda2eb255b44e604246ce084f3139adf43bf3d055fd3584eae
-rw-r--r--+ 1 mmosko  1987151510  1471 Jul  1 22:32 f63d4b208e24ed915a76eddcf89fb9cec86eb18f6d11b5c26da2852b1497bb02
-rw-r--r--+ 1 mmosko  1987151510   490 Jul  1 22:32 f74a2dd53446f597a4659d160945186b31e87f2c43f632dac54a1da033fbe147
```


Packet `44b8f04d36f09a6295447c47c6e0501cbe83382776140e0039d7fe48d3a2c74f` is:

```bash
    {
       Packet: {
          FH: {
             ver: 1,
             pt: 1,
             plen: 217,
             flds: '000000',
             hlen: 8
          },
          CO: {
             None,
             None,
             PLDTYP: 'DATA',
             PAYLOAD: '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
          },
          None,
          None
       }
    }
```

If we did not use encryption, then the output would be even more compressed.  That is because most of the manifest
nodes look just like the other manifest nodes, so we get data de-duplication of manifest nodes.  With encryption,
each manifest node is unique due to different IVs.

In this example without encryption, the entire 1 MB `zeros` file and manifest tree fit in just 7 objects with a total
wire-format size of 7173 bytes.

```bash
ccnpy$ python3 -m ccnpy.apps.manifest_writer  \
                   -n ccnx:/example.com/manifest \
                   -k test_key.pem \
                   -p '' \
                   -s 1500 \
                   -o ./out3  \
                   zeros
                   
Creating manifest tree
Root manifest hash: HashValue: {alg: 'SHA256', val: '96dc49fa08b26d569e652e6dfe2890b901f98f7ed71b57b8084f873bafd61e80'}

ccnpy$ ls -l out3
total 56
-rw-r--r--+ 1 mmosko  1987151510  1489 Jul  1 22:38 1cf93ae7af50140435592e5fc10e07fe5c8ec0e356ceb93c4b847eb2a04373a4
-rw-r--r--+ 1 mmosko  1987151510  1489 Jul  1 22:38 1d9eb906e894ec892eff2f10d6664909668c7d19ba7300cca7c10af5a63db990
-rw-r--r--+ 1 mmosko  1987151510   553 Jul  1 22:38 29f93a68e2402dc163954e21975c6031064b6f82f81773776167a5a9f5b2262f
-rw-r--r--+ 1 mmosko  1987151510  1489 Jul  1 22:38 4037ff9614afd66ef676b6beab14ca93a3cd2ebbb79684f3bded8f93ee3e2f90
-rw-r--r--+ 1 mmosko  1987151510   217 Jul  1 22:38 44b8f04d36f09a6295447c47c6e0501cbe83382776140e0039d7fe48d3a2c74f
-rw-r--r--+ 1 mmosko  1987151510  1500 Jul  1 22:38 81e24663be0c7c9a9e461c03392e30c7f0492fccbe0b59d41ee2913385dbf712
-rw-r--r--+ 1 mmosko  1987151510   436 Jul  1 22:38 96dc49fa08b26d569e652e6dfe2890b901f98f7ed71b57b8084f873bafd61e80
```

# FLIC Manifests

See the IRTF draft on [FLIC](https://datatracker.ietf.org/doc/draft-irtf-icnrg-flic/) for a description of the CCNx objects and grammar.  Below, we provide some
examples to help show how `manifest_writer` works.

A Manifest is embedded inside a CCNx Content Object:

    ManifestContentObject = TYPE LENGTH [Name] [ExpiryTime] PayloadType Payload
    Name = TYPE LENGTH *OCTET ; As per RFC8569
    ExpiryTime = TYPE LENGTH *OCTET ; As per RFC8569
    PayloadType = TYPE LENGTH T_PYLDTYPE_MANIFEST
    Payload : TYPE LENGTH *OCTET ; the serialized Manifest object

## Manifest Examples

NOTE: These examples are a bit old and do not include the revision of putting the
manifest inside the Payload.

Example of a full Manifest node, such as a root manifest

    [FIXED_HEADER OCTET[8]]
    (ContentObject/T_OBJECT
        (Name/T_NAME ...)
        (ExpiryTime/T_EXPIRY 20190630Z000000)
        (Manifest
            (Node
                (NodeData
                    (SubtreeSize 5678)
                    (SubtreeDigest (HashValue SHA256 a1b2...))
                    (Locators (Final FALSE) (Link /example.com/repo))
                )
                (HashGroup
                    (GroupData
                        (SubtreeSize 1234)
                        (SubtreeDigest (HashValue SHA256 abcd...))
                )
                (Pointers
                    (Ptr ...)
                    (Ptr ...)
                )
            )
        )
    )
    (ValidationAlg ...)
    (ValidationPayload ...)


To use an encrypted manifest, create an unencrypted manifest with the SecurityCtx and AuthTag, then do an
in-place encryption with AES-GCM-256. Put the Authentication Tag in the AuthTag value. After the encryption,
change the TLV type of Node to EncryptedNode.
Note that if the publisher should finish the encryption and TLV type changes before signing the ContentObject with the ValidationPayload.

    [FIXED_HEADER OCTET[8]]
    (ContentObject/T_OBJECT
        (Name/T_NAME ...)
        (ExpiryTime/T_EXPIRY 20190630Z000000)
        (Manifest
            (SecurityCtx
                (PresharedKey (KeyNum 55) (IV 8585...) (Mode AES-GCM-256))
            )
            (Node
                (NodeData
                    (SubtreeSize 5678)
                    (SubtreeDigest (HashValue SHA256 a1b2...))
                    (Locators (Final FALSE) (Link /example.com/repo))
                )
                (HashGroup
                    (GroupData
                        (SubtreeSize 1234)
                        (SubtreeDigest (HashValue SHA256 abcd...))
                )
                (Pointers
                    (Ptr ...)
                    (Ptr ...)
                )
            )
            (AuthTag 0x00...)
        )
    )
    (ValidationAlg ...)
    (ValidationPayload ...)

Example of a nameless and encrypted manifest node

    [FIXED_HEADER OCTET[8]]
    (ContentObject/T_OBJECT
        (ExpiryTime/T_EXPIRY 20190630Z000000)
        (Manifest
            (SecurityCtx
                (PresharedKey (KeyNum 55) (IV 8585...) (Mode AES-GCM-256))
            )
            (EncryptedNode ...)
            (AuthTag ...)
        )
    )

After in-place decryption, change type of EncryptedNode to Node
and change AuthTag to PAD and overwrite the value with zeros.

    [FIXED_HEADER OCTET[8]]    
    (ContentObject/T_OBJECT
        (ExpiryTime/T_EXPIRY 20190630Z000000)
        (Manifest
            (SecurityCtx
                (PresharedKey (KeyNum 55) (IV 8585...) (Mode AES-GCM-256))
            )
            (Node ...)
            (PAD ...)
        )
    )

## AEAD Encryption Algorithm

    AeadData := KeyNum Nonce Mode
    KeyNum := INTEGER
    Nonce := OCTET+
    Mode := AES-GCM-128 AES-GCM-256 AES-CCM-128 AES-CCM-256

The KeyNum identifies a key on the receiver. The key must be of the correct length of the Mode used. If the key is
longer, use the left bits. Many receivers many have the same key with the same KeyNum.
A publisher creates a signed root manifest with a security context. A consumer must ensure that 
the root manifest signer is the expected publisher for use with the pre-shared key, which may be shared with 
many other consumers. The publisher may use either method 8.2.1 (deterministic IV) or 8.2.2 (RBG-based IV) 
[NIST 800-38D] for creating the Nonce.  It is also recommended that the publisher and consumers share
a 4-byte salt, which is not transmitted in-band.

Each encrypted manifest node (root manifest or internal manifest) has a full security
context (KeyNum, Nonce, Mode). The AES-GCM decryption is independent for each manifest so Manifest objects can be 
fetched and decrypted in any order. This design also ensures that if a manifest tree points to the same subtree 
repeatedly, such as for deduplication, the decryptions are all idempotent.

The functions for authenticated encryption and authenticated decryption are as given in Sections 7.1 and 7.2 of 
NIST 800-38D: `GCM-AE_K(IV, P, A)` and `GCM-AD_K(IV, C, A, T)`.

    EncryptNode(SecurityCtx, Node, K, IV) -> GCM-AE_K(IV, P, A) -> (C, T)
        Node: The wire format of the Node (P)
        SecurityCtx: The wire format of the SecurityCtx as the Additional Authenticated Data (A)
        K: the pre-shared key (128 or 256 bits)
        IV: The initialization vector (usually 96 or 128 bits)
        C: The cipher text
        T: The authentication tag

The pair (C,T) is the OpaqueNode encoded as a TLV structure:

    (OpaqueNode (CipherText C) (AuthTag T))

    DecryptNode(SecurityCtx, C, T, K, IV) -> GCM-AD_K (IV, C, A, T) -> (Node, FailFlag)
        Node: The wire format of the decrypted Node
        FailFlag: Indicates authenticated decryption failure (true or false)

If doing in-place decryption, the cipher text C will be enclosed in an EncryptedNode TLV value. After decryption, 
change the TLV type to Node. The length should be the same. After decryption the AuthTag is no longer needed. The 
TLV type should be changed to T_PAD and the value zeroed. The SecurityCtx could be changed to T_PAD and zeroed or 
left as-is.

# Implementation notes

## dependencies
   
The dependencies are in the pyproject.toml file for use with `poetry`.

`graphviz` is required on the system if you will use the `ManifestGraph` module generated by `Traversal`.

## Serialization and Deserialization
The class methods `deserialize(buffer)` 
take a byte array (array.array("B", ...)).  They are found in `ccnpy.Packet.deserialize(buffer)`
and `ccnpy.FixedHeader.deserialize(buffer)` and `ccnpy.Tlv.deserialize(buffer)` 
and `ccnpy.Link.deserialize(buffer)`.  Other
classes work at the TLV level via the class method `parse(tlv)`.

Typically, all one needs to do is call `ccnpy.Packet.deserialize(buffer)` or
`ccnpy.Packet.load(filename)` and everthing else is done automatically.

The `serialize()` methods always return a byte array (array.array("B", ...)).
Typically, all one needs to do is call `ccnpy.Packet.serialize()` or `ccnpy.Packet.save(filename)`.

## Building Trees

`ccnpy.flic.tree.TreeBuilder` will construct a pre-order tree in a single pass going from the tail of the data to
the beginning.  This allows us to create all the children of a parent before the parent, which means we can populate
all the hash pointers.

Pre-order traversal and the reverse pre-order traversal are shown below.  In a nutshell, we create the right-most-child
manifest, then its parent, then the indirect pointers of that parent, then the parent's direct pointers, then
the parent of the parent (repeating).  This process uses recursion, as I think it is the clearest way to show
the code.  A more optimized approach could do it in a true single pass.

Here is the pseudocode for `preorder` and `reverse_preorder` traversals of a tree.  The pseudocode below, and the class
`TreeBuilder`, use the `reverse_preorder` approach to building the manifest tree.

    preorder(node)
        if (node = null)
            return
        visit(node)
        preorder(node.left)
        preorder(node.right)

    reverse_preorder(node)
        if (node = null)
            return
        reverse_preorder(node.right)
        reverse_preorder(node.left)
        visit(node)



Because we're building from the bottom up, we use the term 'level' to be the distance from the right-most child
up.  Level 0 is the bottom-most level of the tree, such as where node `7` is:

            1
        2       3
      4  5    6  7
      preorder: 1 2 4 5 3 6 7
      reverse:  7 6 3 5 4 2 1

Here is the pseudo-code for what `TreeBuilder` does:

    build_tree(data[0..n-1], n, k, m)
        # data is the application data
        # n is the number of data items
        # k is the number of direct pointers per internal node
        # m is the number of indirect pointers per internal node

        segment = namedtuple('Segment', 'head tail')(0, n)
        level = 0

        # This bootstraps the process by creating the right most child manifest
        # A leaf manifest has no indirect pointers, so k+m are direct pointers
        root = leaf_manifest(data, segment, k + m)

        # Keep building subtrees until we're out of direct pointers
        while not segment.empty():
            level += 1
            root = bottom_up_preorder(data, segment, level, k, m, root)

        return root

    bottom_up_preorder(data, segment, level, k, m, right_most_child=None)
        manifest = None
        if level == 0:
            assert right_most_child is None
            # build a leaf manifest with only direct pointers
            manifest = leaf_manifest(data, segment, k + m)
        else:
            # If the number of remaining direct pointers will fit in a leaf node, make one of those.
            # Otherwise, we need to be an interior node
            if right_most_child is None and segment.length() <= k + m:
                manifest = leaf_manifest(data, segment, k+m)
            else:
                manifest = interior_manifest(data, segment, level, k, m, right_most_child)
        return manifest

    leaf_manifest(data, segment, count)
        # At most count items, but never go before the head
        start = max(segment.head(), segment.tail() - count)
        manifest = Manifest(data[start:segment.tail])
        segment.tail -= segment.tail() - start
        return manifest

    interior_manifest(data, segment, level, k, m, right_most_child)
        children = []
        if right_most_child is not None:
            children.append(right_most_child)

        interior_indirect(data, segment, level, k, m, children)
        interior_direct(data, segment, level, k, m, children)

        manifest = Manifest(children)
        return manifest, tail

    interior_indirect(data, segment, level, k, m, children)
        # Reserve space at the head of the segment for this node's direct pointers before
        # descending to children.  We want the top of the tree packed.
        reserve_count = min(m, segment.tail - segment.head)
        segment.head += reserve_count

        while len(children) < m and not segment.head == segment.tail:
            child = bottom_up_preorder(data, segment, level - 1, k, m)
            # prepend
            children.insert(0, child)

        # Pull back our reservation and put those pointers in our direct children
        segment.head -= reserve_count

    interior_direct(data, segment, level, k, m, children)
        while len(children) < k+m and not segment.head == segment.tail:
            pointer = data[segment.tail() - 1]
            children.insert(0, pointer)
            segment.tail -= 1
