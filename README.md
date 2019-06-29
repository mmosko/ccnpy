# Pure Python CCNx 1.0

ccnpy is a pure python implementation of the CCNx 1.0
protocols (RFC xxxx and RFC yyyy).


# Application Interface

* ccnpy.apps.manifest_writer: slice up a file into nameless data content objects and organize them into a manifest tree.
    The output packets are written to a file system directory.
* ccnpy.apps.packet_reader: reads a packet from the file system and decodes it.  Still a little messy on the display.
* ccnpy.apps.manifest_reader: given a manifest name, assembles the application data and writes it to a file. (IN PROGRESS)

# Programming Interfaces

* ccnpy: This package has the main CCNx objects.
* ccnpy.flic: The FLIC objects for manifests
* ccnpy.flic.tree: Tree building and related classes.
* ccnpy.flic.presharedkey: The preshared key encryptor/decryptor for manifests
* ccnpy.crypto: Crypto algorithms for AES and RSA.  Used by encryptor/decryptor and ccnpy signers and verifiers.

# Example use to create a Manifest tree from a file:

In this example, we create an RSA key that will be used to sign the root manifest, create a temporary
output directory, and then run `manifest_writer`.

The arguments to `manifest_writer` do the following:
 * -n is the CCNx name of the root manifest
 * -d limits the manifest to a degree 11 tree
 * -k is the RSA signing key filename
 * -p is the RSA key password.  An empty string is used so the program will not prompt us for one.
 * -s is the maximum packet length in bytes
 * -o is the output directory to write packets in wire format
 * --enc-key is the AES key to use to encrypt the manifests as a hex string
 * --key-num is the key identifier
 
```bash
ccnpy$ openssl genrsa -out test_key.pem
ccnpy$ mkdir output
ccnpy$ python3 -m ccnpy.apps.manifest_writer -n ccnx:/example.com/manifest \
                    -d 11 \
                    -k test_key.pem \
                    -p '' \
                    -s 500 \
                    -o ./output \
                    --enc-key 0102030405060708090a0b0c0d0e0f10 \
                    --key-num 22 LICENSE
                    
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

We can look into each of these packets.

```bash
ccnpy$ python3 -m ccnpy.apps.packet_reader -i output \
                --enc-key 0102030405060708090a0b0c0d0e0f10 \
                --key-num 22 \
                47bb45364425f9d081b4d95b4a39456db55dd53e0c6deb770d534c347333e592
                
Packet(FH(1, 1, 490, array('B', [0, 0, 0]), 8), CO(NAME([TLV(1, 11, b'example.com'), TLV(1, 8, b'manifest')]), None, 
    PLDTYP('MANIFEST'), 
    Manifest(PSK(22, array('B', [119, 165, 253, 146, 200, 137, 10, 243, 213, 113, 18, 57]), 'AES-GCM-128'), 
    EncNode(array('B', [249, 16, 190, 170, 252, 54, 195, 27, 68, 176, 164, 156, 226, 236, 77, 71, 192, 194, 30, 143, 130, 30, 144, 39, 32, 109, 142, 69, 43, 8, 162, 108, 131, 18, 145, 42, 181, 35, 148, 85, 198, 153, 83, 38, 10, 73, 52, 200, 248, 120, 17, 223, 183, 124, 155, 136, 126, 168, 47, 137])), 
    AuthTag(array('B', [126, 157, 64, 217, 8, 107, 180, 165, 159, 159, 98, 47, 186, 186, 10, 66])))), 
    {RsaSha256 keyid: HashValue('SHA256', b'c00fdfa98ea156913fb229dd121c1d1f4b32b4c28a557cdeefa04eed59f8bd8e'), pk: None, link: None, time: Timestamp('2019-06-29T13:56:23.910000')}, 
    ValPld(b'234e9de696dc8956586b30f899a0dc9bff1c2db4c155950f32264bd472cc735180beef17a6e4fe44449af0a727857befb98a2e4fb40ed7d9ea4a94f5cedd9ee15391f73fa8a1444861a1ee2809c1d6f023d7e5818fceddf07badf83bdff2bc898d0552993cb642622c10691ccc48b1df9434e1e5bb9bbcf5be0b80a717c66e8a7b9cbdd508569342445f5a49a1aa59ac7aaa620ec225570d779d0a59c502994c5a5d56f7e51e86977727d61d7878aefaace428aa0c2b055d2a6c4bbd4d3767817924fd14dcedef6e0d97edf6342cb4158cce91cb4cb545798f5cac8752cb01eac14ffaa263f40237a5e87349c6bf809ed1de7a1d934557167865f74e2d0c6c70'))
Decryption successful
Manifest(None, Node(NodeData(SubtreeSize(11357), None, None), 1, [HashGroup(None, Ptrs([
    HashValue('SHA256', b'7df97d5162cfa8e22824a9212e93c54f5ba43cc2a395d994284b9d9bf42886fb')]))]), None)
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
ccnpy$ python3 -m ccnpy.apps.packet_reader -i output \
                    --enc-key 0102030405060708090a0b0c0d0e0f10 \
                    --key-num 22 \
                    7df97d5162cfa8e22824a9212e93c54f5ba43cc2a395d994284b9d9bf42886fb

Packet(FH(1, 1, 499, array('B', [0, 0, 0]), 8), CO(None, None, PLDTYP('MANIFEST'), 
    Manifest(PSK(22, array('B', [65, 221, 233, 98, 71, 150, 11, 28, 23, 63, 88, 220]), 'AES-GCM-128'), 
    EncNode(array('B', [58, 247, 190, 55, 181, 72, 229, 93, 179, 137, 23, 206, 81, 16, 97, 180, 95, 10, 138, 2, 2, 225, 248, 143, 20, 105, 65, 63, 207, 4, 121, 183, 79, 204, 161, 76, 62, 155, 25, 163, 249, 7, 22, 115, 171, 118, 206, 129, 119, 18, 89, 210, 166, 44, 147, 239, 246, 208, 202, 12, 21, 149, 30, 176, 64, 79, 255, 8, 213, 92, 1, 95, 55, 207, 160, 201, 131, 131, 61, 235, 235, 220, 200, 81, 187, 137, 34, 220, 109, 219, 185, 5, 27, 107, 128, 197, 77, 42, 84, 95, 23, 19, 74, 207, 212, 209, 245, 174, 118, 193, 42, 103, 187, 159, 149, 49, 189, 6, 93, 71, 137, 160, 218, 97, 37, 197, 175, 208, 215, 106, 59, 44, 182, 35, 85, 184, 110, 81, 97, 68, 123, 24, 62, 89, 174, 24, 108, 157, 178, 28, 16, 111, 214, 33, 179, 27, 202, 157, 65, 59, 182, 9, 238, 68, 45, 125, 99, 244, 231, 199, 28, 99, 109, 122, 155, 139, 161, 29, 48, 197, 174, 12, 156, 107, 182, 215, 164, 108, 34, 38, 70, 39, 164, 71, 198, 7, 71, 209, 230, 192, 100, 145, 34, 195, 203, 237, 208, 142, 150, 235, 110, 207, 233, 118, 155, 170, 85, 193, 93, 213, 59, 50, 101, 50, 232, 17, 227, 224, 35, 131, 207, 183, 228, 18, 11, 153, 249, 188, 2, 201, 211, 255, 182, 241, 212, 0, 76, 221, 30, 227, 226, 164, 199, 102, 227, 228, 105, 91, 64, 179, 67, 145, 178, 48, 36, 133, 13, 18, 199, 161, 20, 115, 241, 187, 165, 197, 84, 232, 180, 93, 18, 247, 202, 203, 19, 80, 68, 135, 64, 180, 103, 45, 134, 149, 21, 65, 106, 107, 60, 184, 56, 214, 154, 96, 48, 54, 226, 90, 190, 47, 210, 122, 199, 160, 63, 15, 156, 30, 207, 119, 134, 127, 49, 61, 68, 53, 224, 58, 229, 157, 101, 86, 248, 77, 226, 131, 182, 50, 203, 240, 159, 186, 225, 118, 166, 200, 167, 194, 32, 232, 50, 145, 176, 93, 105, 68, 55, 61, 32, 63, 254, 24, 47, 38, 36, 233, 211, 84, 13, 126, 154, 162, 234, 91, 235, 116, 163, 159, 50, 36, 95, 229, 136, 227, 132, 148, 168, 192, 153, 7, 226, 221, 104, 38, 140, 189, 126, 169, 233, 185, 51, 80, 20, 223, 183, 87, 129, 250, 24, 221, 61, 145, 162, 36, 139, 159, 16, 178, 228, 212])), 
    AuthTag(array('B', [39, 102, 54, 91, 228, 44, 20, 223, 19, 100, 25, 215, 132, 237, 31, 143])))), None, None)
Decryption successful
Manifest(None, Node(NodeData(SubtreeSize(11357), None, None), 11, [HashGroup(None, Ptrs([
    HashValue('SHA256', b'31065331e00e3eb32fee93c9f2f6339e788d041c32bd242444892c6249e08e90'), 
    HashValue('SHA256', b'e6743bcfb3fbb12daa2bc9f4bbad14e8ec620e82c6b929506167bd324ecaa9f1'), 
    HashValue('SHA256', b'af182acb54e102a5dd1ea4e944a2b0bc04d89aaac5b7d22d860a9cc970d88185'), 
    HashValue('SHA256', b'887335c9ad28820c8c7ea6fdc1a958161e3c853c246038a90787876843cc4f5d'), 
    HashValue('SHA256', b'e3df9814e3f6e030fa90d512b519693f9d87a1e1f893efe4e3a7c2238e966527'), 
    HashValue('SHA256', b'4d2f184d12c10e103898277348a756e1c5bdb592eeb6e2f12cd0dcceed905bac'), 
    HashValue('SHA256', b'83ae6c02983fc75e0eb756d8b6780f3b8ac54bfe46f2886013ea1ec8262a517f'), 
    HashValue('SHA256', b'1da52e06097ebf55200640b24e065976943d661133bbe7376801e10f45c2d1f4'), 
    HashValue('SHA256', b'0c48afc336dfbc04aae31b1c20f159c53ba5d212160ae48015358bcfe1d223fd'), 
    HashValue('SHA256', b'0a88e7d58d1a25cad1cc188c7043c92b6e9ae8764ec6405a5124b086cc7623ac'), 
    HashValue('SHA256', b'71cab6317b43b201d57cd0c524687a9cf7ef302f579c3929bab1899a3d2d8095')]))]), None)
```

# Implementation nodes

## dependencies
   
```python3 -m pip install cryptography crc32c```

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
