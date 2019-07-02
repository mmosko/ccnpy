# Pure Python CCNx 1.0

ccnpy is a pure python implementation of the CCNx 1.0
protocols (RFC xxxx and RFC yyyy).

The implementation focuses on the client libraries used to consume or produce content and to
organize it in manifests.  There is no plan to create a python CCNx forwarder.  Currently,
the code only writes packets, in wire format, to files or reads them from files; there are
no network operations.

The primary use of this code, at the moment, is to prototype the FLIC Manifest specification.   Everything is
still in play at the moment and this is not a final specification or implementation yet.

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

* ccnpy: This package has the main CCNx objects.
* ccnpy.flic: The FLIC objects for manifests
* ccnpy.flic.tree: Tree building and related classes.
* ccnpy.flic.presharedkey: The preshared key encryptor/decryptor for manifests
* ccnpy.crypto: Crypto algorithms for AES and RSA.  Used by encryptor/decryptor and ccnpy signers and verifiers.

## Examples

In this example, we will use `ccnpy.apps.manifest_writer` to split a file into namesless content objects
and construct a manifest tree around them.  First, we look at the command-line for `manifest-writer`.  See below
for background on [CCNx FLIC manifets](#FLIC-Manifests)

```bash
ccnpy$ python3 -m ccnpy.apps.manifest_writer --help
usage: manifest_writer.py [-h] -n NAME [-d TREE_DEGREE] [-k KEY_FILE]
                          [-p KEY_PASS] [-s MAX_SIZE] [-o OUT_DIR]
                          [-l LOCATOR] [--root-expiry ROOT_EXPIRY]
                          [--node-expiry NODE_EXPIRY]
                          [--data-expiry DATA_EXPIRY] [--enc-key ENC_KEY]
                          [--key-num KEY_NUM]
                          filename

positional arguments:
  filename              The filename to split into the manifest

optional arguments:
  -h, --help            show this help message and exit
  -n NAME               root manifest name URI (e.g. ccnx:/example.com/foo)
  -d TREE_DEGREE        manifest tree degree default 7)
  -k KEY_FILE           RSA private key in PEM format to sign the root
                        manifest
  -p KEY_PASS           RSA private key password (otherwise will prompt)
  -s MAX_SIZE           maximum content object size (default 1500)
  -o OUT_DIR            output directory (default='.')
  -l LOCATOR            URI of a locator (root manifest)
  --root-expiry ROOT_EXPIRY
                        Expiry time (ISO format, .e.g
                        2020-12-31T23:59:59+00:00) to expire root manifest
  --node-expiry NODE_EXPIRY
                        Expiry time (ISO format) to expire node manifests
  --data-expiry DATA_EXPIRY
                        Expiry time (ISO format) to expire data nameless
                        objects
  --enc-key ENC_KEY     AES encryption key (hex string)
  --key-num KEY_NUM     Key number of pre-shared key
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
ccnpy$ mkdir output
ccnpy$ python3 -m ccnpy.apps.manifest_writer \
                    -n ccnx:/example.com/manifest \
                    -d 11 \
                    -k test_key.pem \
                    -p '' \
                    -s 500 \
                    -o ./output \
                    --enc-key 0102030405060708090a0b0c0d0e0f10 \
                    --key-num 22 \
                    LICENSE
                    
Creating manifest tree
Root manifest hash: HashValue('SHA256', b'47bb45364425f9d081b4d95b4a39456db55dd53e0c6deb770d534c347333e592'
```

Looking at the output directory, we see that all the CCNx Packets are 500 bytes or less, which is exactly what
we asked for.  The ones exactly 500 bytes are the data content objects.  The others are manifests, which do not
exactly fit in 500 bytes.  The various sizes depend on the number of pointers in each one.  We will look at
packet dumps below.

```bash
ccnpy$ ls -l output
total 224
-rw-r--r--+ 1 mmosko  1987151510  247 Jun 28 23:56 0a88e7d58d1a25cad1cc188c7043c92b6e9ae8764ec6405a5124b086cc7623ac
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 0c48afc336dfbc04aae31b1c20f159c53ba5d212160ae48015358bcfe1d223fd
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 0f5043db4c988440d9803c71e6d4daf47867cdba56e182ccc2e830231a8178fb
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 125fae41a28989145d34ab188fe2190caa4b97011e69446dfe49f5232d609b3b
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 166fc57cad5de9584c3ebdac85a1db968ae41b2d59112ac4818ac3242bf2ff4a
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 1da52e06097ebf55200640b24e065976943d661133bbe7376801e10f45c2d1f4
-rw-r--r--+ 1 mmosko  1987151510  361 Jun 28 23:56 28df0ce6953593d4f869a0a1a45682c52752303329628daf7263dcc3fa8afa4d
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 2b293564ccc0ba4f8f85e8e5a4ef90bb58c429a7a0b388a441b086488a288427
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 31065331e00e3eb32fee93c9f2f6339e788d041c32bd242444892c6249e08e90
-rw-r--r--+ 1 mmosko  1987151510  490 Jun 28 23:56 47bb45364425f9d081b4d95b4a39456db55dd53e0c6deb770d534c347333e592
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 4d2f184d12c10e103898277348a756e1c5bdb592eeb6e2f12cd0dcceed905bac
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 64d8aaebd9f402b833d4c3c64b0b4fed40101f3388a1fa1e0d8eedef4ae23617
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 6698535f4847008068589a117bdb410c17d8d04bf6b91ba5bfcbd43ec49e5f5e
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 67cbb9b8b5ddee8d98311bbcdb792c0adc14171785aca5b1777dd8b2b4a70ed8
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 6d0e16c90c3d8188f7befdd8ce1e72c21d225cc0b52439d3411a4f51b09b5aed
-rw-r--r--+ 1 mmosko  1987151510  499 Jun 28 23:56 71cab6317b43b201d57cd0c524687a9cf7ef302f579c3929bab1899a3d2d8095
-rw-r--r--+ 1 mmosko  1987151510  499 Jun 28 23:56 7df97d5162cfa8e22824a9212e93c54f5ba43cc2a395d994284b9d9bf42886fb
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 83ae6c02983fc75e0eb756d8b6780f3b8ac54bfe46f2886013ea1ec8262a517f
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 887335c9ad28820c8c7ea6fdc1a958161e3c853c246038a90787876843cc4f5d
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 af182acb54e102a5dd1ea4e944a2b0bc04d89aaac5b7d22d860a9cc970d88185
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 b2180a827443e3329fe3863656312ccf1978d212b49975e41499f908d39b9704
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 d246d972b2fe993556041a27d1244a3fe3122105927aaed587448083247d9d4a
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 d7bc2a27eb1c1bf08c31f1de582f7c49acccddee141058ccac5a41988f7d4a6c
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 d9a71da31961aa48e32e5a6b0b3784204984cd1e5a4471226bcd6a32f42c4fe8
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 dfd5474165928f5c87717674fb5f76cf39241a9ea8842ea009870827890dfc59
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 e3df9814e3f6e030fa90d512b519693f9d87a1e1f893efe4e3a7c2238e966527
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 e6743bcfb3fbb12daa2bc9f4bbad14e8ec620e82c6b929506167bd324ecaa9f1
-rw-r--r--+ 1 mmosko  1987151510  500 Jun 28 23:56 f68375a22c5654f1f180c12dc040e8a94cc7aae5edaebfd7ab02a3a92094a47d
```

We can look into each of these packets.  First, look at the root manifest, whose hash-based name was in the
output of `manifest_writer`.

```bash
ccnpy$ python3 -m ccnpy.apps.packet_reader \
                --pretty \
                -i output \
                --enc-key 0102030405060708090a0b0c0d0e0f10 \
                --key-num 22 \
                47bb45364425f9d081b4d95b4a39456db55dd53e0c6deb770d534c347333e592

{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 490,
         flds: '000000',
         hlen: 8
      },
      CO: {
         NAME: [TLV: {
            T: 1,
            L: 11,
            V: 'example.com'
         }, TLV: {
            T: 1,
            L: 8,
            V: 'manifest'
         }],
         None,
         PLDTYP: 'MANIFEST',
         Manifest: {
            PSK: {
               kn: 22,
               iv: '77a5fd92c8890af3d5711239',
               mode: 'AES-GCM-128'
            },
            EncNode: 'f910beaafc36c31b44b0a49ce2ec4d47c0c21e8f821e9027206d8e452b08a26c8312912ab5239455c69953260a4934c8f87811dfb77c9b887ea82f89',
            AuthTag: '7e9d40d9086bb4a59f9f622fbaba0a42'
         }
      },
      RsaSha256: {
         keyid: HashValue: {
            alg: 'SHA256',
            val: 'c00fdfa98ea156913fb229dd121c1d1f4b32b4c28a557cdeefa04eed59f8bd8e'
         },
         pk: None,
         keylink: None,
         'SignatureTime': '2019-06-29T13:56:23.910000'
      },
      ValPld: '234e9de696dc8956586b30f899a0dc9bff1c2db4c155950f32264bd472cc735180beef17a6e4fe44449af0a727857befb98a2e4fb40ed7d9ea4a94f5cedd9ee15391f73fa8a1444861a1ee2809c1d6f023d7e5818fceddf07badf83bdff2bc898d0552993cb642622c10691ccc48b1df9434e1e5bb9bbcf5be0b80a717c66e8a7b9cbdd508569342445f5a49a1aa59ac7aaa620ec225570d779d0a59c502994c5a5d56f7e51e86977727d61d7878aefaace428aa0c2b055d2a6c4bbd4d3767817924fd14dcedef6e0d97edf6342cb4158cce91cb4cb545798f5cac8752cb01eac14ffaa263f40237a5e87349c6bf809ed1de7a1d934557167865f74e2d0c6c70'
   }
}

Decryption successful
Manifest: {
   None,
   Node: {
      NodeData: {
         SubtreeSize: 11357,
         None,
         None
      },
      1,
      [HashGroup: {
         None,
         Ptrs: [HashValue: {
            alg: 'SHA256',
            val: '7df97d5162cfa8e22824a9212e93c54f5ba43cc2a395d994284b9d9bf42886fb'
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

The next manifest decodes as below.  This is a nameless content object: there is no name and there is no validation,
we only refer to it by its hash name.  The decryption shows that the manifest has 11 hash pointers, which is what
we limited the tree to.  Most of those are direct data pointers and the last few will be indirect manifest
pointers.  A quick scan of the file list above shows that the `1da...` file is the last in the list to be
exactly 500 bytes, so there are 8 direct pointers and 3 indirect pointers.

```bash
ccnpy$ python3 -m ccnpy.apps.packet_reader \
                    --pretty \
                    -i output \
                    --enc-key 0102030405060708090a0b0c0d0e0f10 \
                    --key-num 22 \
                    7df97d5162cfa8e22824a9212e93c54f5ba43cc2a395d994284b9d9bf42886fb

{
   Packet: {
      FH: {
         ver: 1,
         pt: 1,
         plen: 499,
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
               iv: '41dde96247960b1c173f58dc',
               mode: 'AES-GCM-128'
            },
            EncNode: '3af7be37b548e55db38917ce511061b45f0a8a0202e1f88f1469413fcf0479b74fcca14c3e9b19a3f9071673ab76ce81771259d2a62c93eff6d0ca0c15951eb0404fff08d55c015f37cfa0c983833debebdcc851bb8922dc6ddbb9051b6b80c54d2a545f17134acfd4d1f5ae76c12a67bb9f9531bd065d4789a0da6125c5afd0d76a3b2cb62355b86e5161447b183e59ae186c9db21c106fd621b31bca9d413bb609ee442d7d63f4e7c71c636d7a9b8ba11d30c5ae0c9c6bb6d7a46c22264627a447c60747d1e6c0649122c3cbedd08e96eb6ecfe9769baa55c15dd53b326532e811e3e02383cfb7e4120b99f9bc02c9d3ffb6f1d4004cdd1ee3e2a4c766e3e4695b40b34391b23024850d12c7a11473f1bba5c554e8b45d12f7cacb1350448740b4672d869515416a6b3cb838d69a603036e25abe2fd27ac7a03f0f9c1ecf77867f313d4435e03ae59d6556f84de283b632cbf09fbae176a6c8a7c220e83291b05d6944373d203ffe182f2624e9d3540d7e9aa2ea5beb74a39f32245fe588e38494a8c09907e2dd68268cbd7ea9e9b9335014dfb75781fa18dd3d91a2248b9f10b2e4d4',
            AuthTag: '2766365be42c14df136419d784ed1f8f'
         }
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
         None
      },
      11,
      [HashGroup: {
         None,
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
            val: '0c48afc336dfbc04aae31b1c20f159c53ba5d212160ae48015358bcfe1d223fd'
         }, HashValue: {
            alg: 'SHA256',
            val: '0a88e7d58d1a25cad1cc188c7043c92b6e9ae8764ec6405a5124b086cc7623ac'
         }, HashValue: {
            alg: 'SHA256',
            val: '71cab6317b43b201d57cd0c524687a9cf7ef302f579c3929bab1899a3d2d8095'
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
ccnpy$ python3 -m ccnpy.apps.manifest_writer  \
                   -n ccnx:/example.com/manifest \
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

    Manifest := SecurityCtx? (EncryptedNode / Node) AuthTag?

    SecurityCtx := AlgorithmId AlgorithmData
    AlgorithmId := PresharedKey / RsaKem / INTEGER
    AlgorithmData := PresharedKeyData / RsaKemData / OCTET* ; Algorithm dependent data
    
    AuthTag := OCTET* ; e.g. AEAD authentication tag
    EncryptedNode := OCTET* ; Encrypted Node

    Node := NodeData? HashGroup+
    NodeData := SubtreeSize? SubtreeDigest? Locators?
    SubtreeSize := INTEGER
    SubtreeDigest := HashValue
    
    Locators := Final? Link+
    Final := TRUE / FALSE
    HashValue := ; See RFC 8506
    Link := ; See RFC 8506
    
    HashGroup := GroupData? Pointers
    Pointers := HashValue+
    GroupData := LeafSize? LeafDigest? SubtreeSize? SubtreeDigest? SizeIndex? Locators?
    LeafSize := INTEGER
    LeafDigest := HashValue
    
    SizeIndex := INTEGER+ ; Array of integers same size as Ptr array
    
    PresharedKey := %x0001
    PresharedKeyData := KeyNum IV Mode
    KeyNum := INTEGER
    IV := OCTET+
    Mode := AES-GCM-128 AES-GCM-256
    
    RsaKem := %0x0002
    RsaKemData := KeyId IV Mode WrappedKey LocatorPrefix
    KeyId := HashValue
    WrappedKey := OCTET+    
    LocatorPrefix := Link

A Manifest is embedded inside a CCNx Content Object:

    ManifestContentObject := Name? ExpiryTime? PayloadType Payload
    Name := the ccnx name of the manifest, used for a root manifest.
    ExpiryTime: As per RFC8659
    PayloadType: T_PYLDTYPE_MANIFEST ; TBD
    Payload: OCTET* ; the serialized Manifest object
    
    
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
* Pointers: A list of one or more Hash Values
* GroupData: Metadata that applies to a HashGroup
* LeafSize: Size of all application data immediately under the Group (i.e. without recursion through other Manifests)
* LeafDigest: Digest of all application data immediately under the Group
* SubtreeSize: Size of all application data under the Group (i.e., with recursion)
* SubtreeDigest: Digest of all application data under the Group (i.e. with recursion)
* SizeIndex: An array of the same size as the Ptr array with the recursive size of application data under that Ptr
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
