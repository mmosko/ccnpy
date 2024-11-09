# Pure Python CCNx 1.0

ccnpy is a pure python implementation of the CCNx 1.0
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

```bash
ccnpy$ poetry run manifest_writer --help
usage: manifest_writer [-h] [--schema {Hashed,Prefix,Segmented}] --name NAME [--manifest-locator MANIFEST_LOCATOR] [--data-locator DATA_LOCATOR] [--manifest-prefix MANIFEST_PREFIX]
                       [--data-prefix DATA_PREFIX] [-d TREE_DEGREE] [-k KEY_FILE] [-p KEY_PASS] [--enc-key ENC_KEY] [--key-num KEY_NUM] [-s MAX_SIZE] [-o OUT_DIR] [-T]
                       [--root-expiry ROOT_EXPIRY] [--node-expiry NODE_EXPIRY] [--data-expiry DATA_EXPIRY]
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
  -k KEY_FILE           RSA private key in PEM format to sign the root manifest
  -p KEY_PASS           RSA private key password (otherwise will prompt)
  --enc-key ENC_KEY     AES encryption key (hex string)
  --key-num KEY_NUM     Key number of pre-shared key (defaults to key hash)
  -s MAX_SIZE           maximum content object size (default 1500)
  -o OUT_DIR            output directory (default='.')
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

### Small Packet Example

We create an RSA key that will be used to sign the root manifest, create a temporary
output directory, and then run `manifest_writer`.  We limit the tree to node degree 11
and a maximum packet size of 500 bytes.  Using at 1500 byte packet will allow a tree degree
of 41.  Internally, `ccnpy.flic.tree.TreeOptimizer` calculates the best tradeoff between
direct and indirect pointers per internal manifest node to minimize the waste in the tree,
so you do not need to specify the exact fanout.
    
```bash
ccnpy$ openssl genrsa -out test_key.pem
ccnpy$ mkdir output
ccnpy$ poetry run manifest_writer \
                    --name ccnx:/example.com/manifest \
                    -d 11 \
                    -k test_key.pem \
                    -p '' \
                    -s 500 \
                    -o ./output \
                    --enc-key 0102030405060708090a0b0c0d0e0f10 \
                    --key-num 22 \
                    LICENSE
                    
Creating manifest tree
Root manifest hash: HashValue: {alg: 'SHA256', val: 'e88e4a595e8e16f3e4a3c9452e4f0e184a7b2a73605a5f0bf624930e6c7718d7'}
```

Looking at the output directory, we see that all the CCNx Packets are 500 bytes or less, which is exactly what
we asked for.  The ones exactly 500 bytes are the data content objects.  The others are manifests, which do not
exactly fit in 500 bytes.  The various sizes depend on the number of pointers in each one.  We will look at
packet dumps below.

```bash
ccnpy$ ls -lgo output
-rw-r--r--@ 1   500 Nov  8 12:12 0c48afc336dfbc04aae31b1c20f159c53ba5d212160ae48015358bcfe1d223fd
-rw-r--r--@ 1   500 Nov  8 12:12 0f5043db4c988440d9803c71e6d4daf47867cdba56e182ccc2e830231a8178fb
-rw-r--r--@ 1   500 Nov  8 12:12 125fae41a28989145d34ab188fe2190caa4b97011e69446dfe49f5232d609b3b
-rw-r--r--@ 1   500 Nov  8 12:12 166fc57cad5de9584c3ebdac85a1db968ae41b2d59112ac4818ac3242bf2ff4a
-rw-r--r--@ 1   500 Nov  8 12:12 1da52e06097ebf55200640b24e065976943d661133bbe7376801e10f45c2d1f4
-rw-r--r--@ 1   361 Nov  8 12:12 28df0ce6953593d4f869a0a1a45682c52752303329628daf7263dcc3fa8afa4d
-rw-r--r--@ 1   500 Nov  8 12:12 2b293564ccc0ba4f8f85e8e5a4ef90bb58c429a7a0b388a441b086488a288427
-rw-r--r--@ 1   500 Nov  8 12:12 31065331e00e3eb32fee93c9f2f6339e788d041c32bd242444892c6249e08e90
-rw-r--r--@ 1   500 Nov  8 12:12 4d2f184d12c10e103898277348a756e1c5bdb592eeb6e2f12cd0dcceed905bac
-rw-r--r--@ 1   500 Nov  8 12:12 64d8aaebd9f402b833d4c3c64b0b4fed40101f3388a1fa1e0d8eedef4ae23617
-rw-r--r--@ 1   500 Nov  8 12:12 6698535f4847008068589a117bdb410c17d8d04bf6b91ba5bfcbd43ec49e5f5e
-rw-r--r--@ 1   500 Nov  8 12:12 67cbb9b8b5ddee8d98311bbcdb792c0adc14171785aca5b1777dd8b2b4a70ed8
-rw-r--r--@ 1   328 Nov  8 12:12 6a55fec71d85f32f69dda3fd85f454600639636a77a72c474611fccdb4ece8b6
-rw-r--r--@ 1   500 Nov  8 12:12 6d0e16c90c3d8188f7befdd8ce1e72c21d225cc0b52439d3411a4f51b09b5aed
-rw-r--r--@ 1   500 Nov  8 12:12 83ae6c02983fc75e0eb756d8b6780f3b8ac54bfe46f2886013ea1ec8262a517f
-rw-r--r--@ 1   500 Nov  8 12:12 887335c9ad28820c8c7ea6fdc1a958161e3c853c246038a90787876843cc4f5d
-rw-r--r--@ 1   500 Nov  8 12:12 af182acb54e102a5dd1ea4e944a2b0bc04d89aaac5b7d22d860a9cc970d88185
-rw-r--r--@ 1   500 Nov  8 12:12 b2180a827443e3329fe3863656312ccf1978d212b49975e41499f908d39b9704
-rw-r--r--@ 1   472 Nov  8 12:12 c5fad240d7641fee6160bc52ddba6d90da92d44fe49267d1cc58bc3abe6a2784
-rw-r--r--@ 1   500 Nov  8 12:12 d246d972b2fe993556041a27d1244a3fe3122105927aaed587448083247d9d4a
-rw-r--r--@ 1   500 Nov  8 12:12 d7bc2a27eb1c1bf08c31f1de582f7c49acccddee141058ccac5a41988f7d4a6c
-rw-r--r--@ 1   500 Nov  8 12:12 d9a71da31961aa48e32e5a6b0b3784204984cd1e5a4471226bcd6a32f42c4fe8
-rw-r--r--@ 1   500 Nov  8 12:12 dfd5474165928f5c87717674fb5f76cf39241a9ea8842ea009870827890dfc59
-rw-r--r--@ 1   472 Nov  8 12:12 e3285eba81a97943219e9364201b8c74ece86a89b8f121fb1501f1b6faf249c1
-rw-r--r--@ 1   500 Nov  8 12:12 e3df9814e3f6e030fa90d512b519693f9d87a1e1f893efe4e3a7c2238e966527
-rw-r--r--@ 1   500 Nov  8 12:12 e6743bcfb3fbb12daa2bc9f4bbad14e8ec620e82c6b929506167bd324ecaa9f1
-rw-r--r--@ 1   350 Nov  8 12:12 e88e4a595e8e16f3e4a3c9452e4f0e184a7b2a73605a5f0bf624930e6c7718d7
-rw-r--r--@ 1   500 Nov  8 12:12 f68375a22c5654f1f180c12dc040e8a94cc7aae5edaebfd7ab02a3a92094a47d
```

We can look into each of these packets.  First, look at the root manifest, whose hash-based name was in the
output of `manifest_writer`.  `packet_reader` can use either a private key or public key to verify the
signature on a CCNx packet.  We show the usage with a public key, but the syntax is the same for a private key.
Note that after displaying the content object, it shows "Packet validation success..." before the decrypted packet.

The hash showin the `RsaSha256Verifier` is the public key ID.  You can verify this on the CLI with:
```openssl rsa -pubin -in test_key.pub -outform DER | openssl sha256```.

```bash
ccnpy$ openssl rsa -pubout -in test_key.pem -out test_key.pub
ccnpy$ poetry run packet_reader \
                --pretty \
                -i output \
                --enc-key 0102030405060708090a0b0c0d0e0f10 \
                --key-num 22 \
                -k test_key.pub \
                e88e4a595e8e16f3e4a3c9452e4f0e184a7b2a73605a5f0bf624930e6c7718d7

{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 350,
         flds: '000000',
         hlen: 8
      },
      CO: {
         NAME: [TLV: {
            T: 1,
            L: 11,
            V: b 'example.com'
         }, TLV: {
            T: 1,
            L: 8,
            V: b 'manifest'
         }],
         None,
         PLDTYP: 'MANIFEST',
         Manifest: {
            PSK: {
               kn: 22,
               iv: '511bcb41bfc00297e87e713e',
               mode: 'AES-GCM-128'
            },
            EncNode: '74c41a189faeac83824a7bb889f1690b31c3929e56238d66eb06846ff1898dffab5b8289140c35c533141c93a52d41cc54c5bc8feb7049efe8394999018590846471ff269c6a3e42443472cfc1276ff65087cc1206e9e1b2dfc19174dfcc612dfa63f295ec88581c81409d5a7604be28',
            AuthTag: '7c6ddd29728212f1498d24e2cdca87a8'
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
         'SignatureTime': '2024-11-08T20:12:40.102000+00:00'
      },
      ValPld: '9d098374bc183441394b5dbce5a97c44b3434ae558635c4da12554fac0882413a4a83cfbce148d7d01402945c4766be9c73ff28503f4fd543d99bb4850c07a21'
   }
}

Packet validation success with RsaSha256Verifier(HashValue: {alg: 'SHA256', val: 'c94f873e56e52e317d405dcd9c293baa0ed1f04c12b0e0b3a1ba88c08ceb1044'})
Decryption successful
Manifest: {
   None,
   Node: {
      NodeData: {
         SubtreeSize: 11357,
         None,
         None,
         [NCDEF: (NCID: 1, HS: Locators: [Locator: Link(NAME: [TLV: {
            T: 1,
            L: 11,
            V: b 'example.com'
         }, TLV: {
            T: 1,
            L: 8,
            V: b 'manifest'
         }], None, None)], None)],
         None
      },
      1,
      [HashGroup: {
         None,
         Ptrs: [HashValue: {
            alg: 'SHA256',
            val: 'e3285eba81a97943219e9364201b8c74ece86a89b8f121fb1501f1b6faf249c1'
         }]
      }]
   },
   None
}
```

This is the root manifest from above.  The packet dump shows it is a `PLDTYP('MANIFEST')` so the contents of the
Payload field are a serialized manifest.  The manifest shown is encrypted, so all we can see here is the pre-shared
key context (PSK(...)) that identifies the decryption key, the encrypted node, and the authentication tag.  The 
manifest's content object also has an RsaSha256 validation alg and validation payload.

Because we provided the correct decryption key and key number on the command-line, `PacketReader` also decrypted
the manifest.  This shows there is a Node with NodeData and a subtree size of 11,357 bytes (the filesize of LICENSE).
There is 1 HashGroup with one pointer, as is normal for the named and signed root manifest.

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
                    --enc-key 0102030405060708090a0b0c0d0e0f10 \
                    --key-num 22 \
                    e3285eba81a97943219e9364201b8c74ece86a89b8f121fb1501f1b6faf249c1
{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 472,
         flds: '000000',
         hlen: 8
      },
      CO: {
         None,
         None,
         PLDTYP: 'MANIFEST',
         Manifest: {
            PSK: {
               kn: 22,
               iv: 'c533a506acce6b43843ae8bd',
               mode: 'AES-GCM-128'
            },
            EncNode: 'dd848460cd05d030da1c0b5c8b75c2ac3b5abc7572e0a601c1e1b7b29c369552f106f9dc04d4eb2a66b64ce8c7373fe8963892d374fd857ac6b03fc048a9ea956b2ecbaa341910af68e2161a3318a6acb8a32f0a6e71772296f5c9e10a9030c9e486a7dcab010e3bdbc5d47bae48477411416854323b9142430dd03d95630a6dbc7e015f001a1aafbfc616985799c0dde3a4d2376e0a6b1559e857afe9cffd02c054425a5ec47e96d4b49907e371773a48d96af914557e9d7b4a3b8d4282b3a4b949c417d5734c1202a68d00b82621f8f62031f2a81885bba6b1d9eac8ad7714df30befcd0e00e33ce9e76cf4f58a18aa9e5dabe02e229d3090dd2e3c7563f347991ff11f0b7c45f01cdd35b7090453fbba1081849cadecb51db8991e6a31fd6513854ebc47f6bcf7ed7e8793003a0269575a26277641dcc8482a248c209b585238e802a30ae68155bd07bf69373428119b8b94443a8bb42f87ab9f050b4014163689839cef833f653ddd028e205cacf0ccf6d1dda8577a751cb1fb82a45cfe3ecb598cd19fcca3935',
            AuthTag: '1db8fa20372a9e00d529fed4e91be487'
         },
         None
      },
      None,
      None
   }
}

Decryption successful
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
            val: '6a55fec71d85f32f69dda3fd85f454600639636a77a72c474611fccdb4ece8b6'
         }, HashValue: {
            alg: 'SHA256',
            val: 'c5fad240d7641fee6160bc52ddba6d90da92d44fe49267d1cc58bc3abe6a2784'
         }]
      }]
   },
   None
}

```

### Large Degree Tree

We create a 1MiB file that has all zeros and put it in a Manifest limited to 1500 byte packets.  This should
create only one or two nameless data objects, then a tree with many pointers to the same zeros.

```bash
ccnpy$ dd if=/dev/zero of=zeros bs=1000 count=1000
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

If we did not use encryption, then the output would be even more compressed.  That is because most of the manifest
nodes look just like the other manifest nodes, so we get data de-duplication of manifest nodes.  With encryption,
each manifest node is unique due to different IVs.

```
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

A FLIC manifest is a way of organizing hash pointers to hash-named data objects.

Terminology:
* Data Object: A CCNx nameless Content Object that usually only has Payload.  It might also have an ExpiryTime to
try a limit the lifetime of the data.
* Direct Pointer: Borrowed from inode terminology, it is a CCNx link using a content object hash restriction and a
locator name to point to a Data Object.
* Indirect Pointer: Borrowed from inode terminology, it is a CCNx link using a content object hash restriction and
a locator name to point to a manifest content object.
* Manifest: A CCNx ContentObject with PayloadType 'Manifest' and a Payload of the encoded manifest.  A leaf manifest
only has direct pointers.  An internal manifest has a mixture of direct and indirect manifests.
* Leaf Manifest: all pointers are direct pointers.
* Internal Manifest: some pointers are direct and some pointers are indirect.  The order and number of each is up to
the manifest builder.  Typically, all the direct manifests come first, then the indirect.
* Manifest Waste: a metric used to measure the amount of waste in a manifest tree.  Waste is the number of unused
pointers.  For example, a leaf manifest might be able to hold 40 direct pointers, but only 30 of them are used, so
the waste of this node is 10.  Manifest tree waste is the sum of waste over all manifests in a tree.
* Root Manifest: A signed, named, manifest that points to nameless manifest nodes.  This structure means that the
internal tree structure of internal and leaf manifests have no names and thus may be put located anywhere, while
the root manifest has a name to fetch it by.  


## Grammar (ABNF)

    TYPE = INTEGER ; As per TLV encoding
    LENGTH = INTEGER ; As per TLV encoding
    
    Manifest = TYPE LENGTH [SecurityCtx] (EncryptedNode / Node) [AuthTag]

    SecurityCtx = TYPE LENGTH AlgorithmCtx
    AlgorithmCtx = PresharedKeyCtx /     
    AuthTag = TYPE LENGTH *OCTET ; e.g. AEAD authentication tag
    EncryptedNode = TYPE LENGTH *OCTET ; Encrypted Node

    Node = TYPE LENGTH [NodeData] 1*HashGroup
    NodeData = TYPE LENGTH [SubtreeSize] [SubtreeDigest] [Locators] [NSDef]
    SubtreeSize = TYPE LENGTH INTEGER
    SubtreeDigest = TYPE LENGTH HashValue
    NSDef = TYPE LENGTH NsId NsSchema
    NsId = TYPE LENGTH INTEGER
    NsSchema = HashSchema / SinglePrefixSchema / SegmentedPrefixSchema
    HashSchema = TYPE 0
    SinglePrefixSchema = TYPE LENGTH Name
    SegmentedPrefixSchema = TYPE LENGTH Name
    
    Locators = TYPE LENGTH 1*Link
    HashValue = TYPE LENGTH *OCTET ; See RFC 8506 or NDN ImplicitSha256DigestComponent
    Link = TYPE LENGTH *OCTET ; See RFC 8506 Link or NDN Delegation (from Link Object)
     
    HashGroup = TYPE LENGTH [GroupData] (Ptrs / AnnotatedPtrs)
    Ptrs = TYPE LENGTH *HashValue
    AnnotatedPtrs = TYPE LENGTH *PointerBlock
    PointerBlock = TYPE LENGTH *Annotation Ptr
    Ptr = TYPE LENGTH HashValue
    Annotation = SizeAnnotation / Vendor

    GroupData = TYPE LENGTH [LeafSize] [LeafDigest] [SubtreeSize] [SubtreeDigest] [NsId]
    LeafSize = TYPE LENGTH INTEGER
    LeafDigest = TYPE LENGTH HashValue
    
    PresharedKeyCtx = 1 LENGTH PresharedKeyData
    PresharedKeyData = KeyNum IV Mode
    KeyNum = TYPE LENGTH INTEGER
    IV = TYPE LENGTH 1*OCTET
    Mode = TYPE LENGTH (AES-GCM-128 / AES-GCM-256)
    
    RsaKemCtx = 2 LENGTH RsaKemData
    RsaKemData = KeyId IV Mode WrappedKey LocatorPrefix
    KeyId = TYPE LENGTH HashValue 
    WrappedKey = TYPE LENGTH 1*OCTET    
    LocatorPrefix = TYPE LENGTH Link

A Manifest is embedded inside a CCNx Content Object:

    ManifestContentObject = TYPE LENGTH [Name] [ExpiryTime] PayloadType Payload
    Name = TYPE LENGTH *OCTET ; As per RFC8569
    ExpiryTime = TYPE LENGTH *OCTET ; As per RFC8569
    PayloadType = TYPE LENGTH T_PYLDTYPE_MANIFEST ; Value TBD
    Payload : TYPE LENGTH *OCTET ; the serialized Manifest object
    
    
## Grammar Description

* Name: The optional ContentObject name
* SecurityCtx: Information about how to decrypt an EncryptedNode. The structure will depend on the specific encryption algorithm.
* AlgorithmId: The ID of the encryption method (e.g. preshared key, a broadcast encryption scheme, etc.)
* AlgorithmData: The context for the encryption algorithm.
* EncryptedNode: An opaque octet string with an optional authentication tag (i.e. for AEAD authentication tag)
* Node: A plain-text manifest node. The structure allows for in-place encryption/decryption.
* NodeData: the metadata about the Manifest node
* SubtreeSize: The size of all application data at and below the Node
* SubtreeDigest: The cryptographic digest of all application data at and below the Node
* Locators: An array of routing hints to find the manifest components
* Final: A flag that prevents Locators from being superseded by a child Manifest Node
* HashGroup: A set of child pointers and associated metadata
* Ptrs: A list of one or more Hash Values
* GroupData: Metadata that applies to a HashGroup
* LeafSize: Size of all application data immediately under the Group (i.e. without recursion through other Manifests)
* LeafDigest: Digest of all application data immediately under the Group
* SubtreeSize: Size of all application data under the Group (i.e., with recursion)
* SubtreeDigest: Digest of all application data under the Group (i.e. with recursion)
* Ptr: The ContentObjectHash of a child, which may be a data ContentObject (i.e. with Payload) or another Manifest Node.
* PresharedKey related fields are described below under Preshared Key Algorithm

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

## PresharedKey Algorithm

    PresharedKeyData := KeyNum IV Mode
    KeyNum := INTEGER
    IV := OCTET+
    Mode := AES-GCM-128 AES-GCM-256

The KeyNum identifies a key on the receiver. The key must be of the correct length of the Mode used. If the key is
longer, use the left bits. Many receivers many have the same key with the same KeyId.
A publisher creates a signed root manifest with a security context. A consumer must ensure that 
the root manifest signer is the expected publisher for use with the pre-shared key, which may be shared with 
many other consumers. The publisher may use either method 8.2.1 (deterministic IV) or 8.2.2 (RBG-based IV) 
[NIST 800-38D] for creating the IV.

Each encrypted manifest node (root manifest or internal manifest) has a full security

context (KeyNum, IV, Mode). The AES-GCM decryption is independent for each manifest so Manifest objects can be 
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


## RSA/EC Key Wrapping Method

Similar to Key Encapsulation, but use something like RSA-PSS or RSA-OAEP or EC-KEM 
[NIST Special Publication 800-56A Rev 3] or EC-MQV.  We could also look at existing
IETF work, e.g. Cryptographic Message Syntax (CMS).

## RSA Key Encapsulation Method

* See also RFC 5990
* See also NIST SP 800-56B Rev. 2
* See also https://lists.w3.org/Archives/Public/public-xmlsec/2009May/att-0032/Key_Encapsulation.pdf

In this system, a key manager (KM) (which could be the publisher) creates a Content
Encryption Key (CEK) and a key wrapping pair with a Key Encryption Key (KEK) and Key Decryption Key (KDK). 
Each publisher and consumer has its own public/private key pair, and the KM knows each publisher’s and consumer’s 
identity and its public key (PK_x).

We do not describe the publisher-key manager protocol to request a CEK. The publisher will obtain the 
(CEK, E_KEK(Z), KeyId, Locator), where each element is: the content encryption key, the CEK precursor, Z, 
encrypted with the KEK (an RSA operation), and the KeyId of the corresponding KDK, and the Locator is the CCNx 
name prefix to fetch the KDK (see below). The precursor Z is chosen randomly z < n-1, where n is KEK’s public modulus. 
Note that CEK = KDF(Z). Note that the publisher does not see KEK or Z.

We use HKDF (RFC 5869) for the KDF. CEK = HKDF-Expand(HKDF-Extract(0, Z), ‘CEK’, KeyLen), where KenLen is usually 
32 bytes (256 bits).

    RsaKemData := KeyId IV Mode WrappedKey LocatorPrefix
    KeyId := HashValue
    IV := OCTET+
    Mode := AES-GCM-128 AES-GCM-256
    WrappedKey := OCTET+
    LocatorPrefix := Link
    KeyId: the ID of the KDK
    IV: The initialization vector for AES-GCM
    Mode: The encryption mode for the Manifest’s EncryptedNode value
    WrappedKey: E_KEK(Z)
    LocatorPrefix: Link with name = KM prefix, KeyId = KM KeyId

To fetch the KDK, a consumer with public key PK_c constructs an Interest with name 
`/LocatorPrefix/<KeyId>/<PK_c keyid>` and a KeyIdRestriction of the KM’s KeyId 
(from the LocatorPrefix Link). It should receive back a signed Content Object with the KDK wrapped for the 
consumer, or a NAK from the KM. The payload of the ContentObject will be RsaKemWrap(PK, KDK). The signed 
ContentObject must have a KeyLocator to the KM’s public key. The consumer will trust the KM’s public key because 
the publisher, whom the consumer trusts, relayed that KeyId inside its own signed Manifest.

The signed Content Object should have an ExpiryTime, which may be shorter than the Manifest’s, but should not 
be substantially longer than the Manifest’s ExpiryTime. The KM may decide how to handle the Recommended Cache Time, 
or if caching of the response is even permissible. The KM may require on-line fetching of the response via a 
CCNxKE encrypted transport tunnel.

    RsaKemWrap(PK, K, KeyLen = 256):    
        choose a z < n-1, where n is PK’s public modulus
        encrypt c = z^e mod n
        prk = HKDF-Extract(0, Z)
        kek = HKDF-Expand(prk, ‘RsaKemWrap’, KeyLen)
        wrap WK = E_KEK(K) [AES-WRAP, RFC 3394]
        output (c, WK)

A consumer must verify the signed content object’s signature against the Key Manager’s public key. The consumer 
then unwraps the KDK from the Content Object’s payload using RsaKemUnwrap(). The KeyLen is taken from the WrapMode 
parameter.

    RsaKemUnwrap(SK, c, WK, KeyLen = 256):
        Using the consumers private key SK, decrypt Z from c.
        prk = HKDF-Extract(0, Z)
        kek = HKDF-Expand(prk, ‘RsaKemWrap’, KeyLen)
        K = D_KEK(WK) [AES-UNWRAP, RFC 33940]
        output K

The consumer then unwraps the CEK precursor by using the KDK to decrypt Z. It then derives CEK as above.

Manifest encryption and decryption proceed as with PresharedKey, but using the CEK.

##  Broadcast Encryption Method

WORK IN PROGRESS

* See Boneh, Dan, Craig Gentry, and Brent Waters. "Collusion resistant broadcast encryption with short ciphertexts 
and private keys." In Annual International Cryptology Conference, pp. 258-275. Springer, Berlin, Heidelberg, 2005.

The Key Manager (KM) knows all consumers and each consumers RSA/EC public key. Each consumer has an ID

The publisher requests a key from the KM for a set of consumers identities or pre-defined groups, and receives 
(HDR, K, KeyId(PK), S, LocatorPrefix).

    BEMData := KeyId IV Mode HDR S LocatorPrefix

# Implementation notes

## dependencies
   
```python3 -m pip install cryptography crc32c jsbeautifier```

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
