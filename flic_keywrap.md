Here is a proposal for key wrapping in FLIC.

Summary:

A Key Manager (KM) manages groups. It issues each group a long-term (until membership changes).

The KM publishes /key_manager/somewhere/`<group_name>`/`<version>` with a link to the current key's namespace: /key_manager/somewhere/<ID(GPK)>. In CCNx, it also publishes a short-lived /key_manager/somewhere/`<group_name>` that points to the current version. However, the normal lookup scheme is from a manifest up to the group key. The RSA group key is GPK/GSK (public/secret keys).

Each user has a UPK/USK (user public/secret key), and the KM knows the UPK. It publishes these under /key_manager/somewhere/<ID(GPK)>/<ID(UPK)> as a content object that holds the GSK encrypted under UPK using RSA-OAEP (see RsaKeyWrap() below). We take ID(.) to be SHA256(.). The KM can be the same as the publisher.

If using Proxy Re-encryption (e.g. [Ateniese, "third attempt"]), the KM creates a re-encryption key pair. It publishes the long-term public key and each user's long-term re-encryption key (which could be generated on-demand), encrypted for that user. It creates a GSK for the group and performs a second level encryption using the long-term public key. Each user may fetch that single object and re-encrypt it to a level 1 encryption that it can then decrypt with its long-term secret key. As per Ateniese, in this scheme the publisher could create the GSK and make a level 2 encryption using the KM's public key and publish it under its own namespace and users could decrypt it using their re-encryption key. This avoids the KM knowing the GSK. [Wang] is another possibility.

A Publisher creates a wrapping key pair (WPK/WSK), such as from ECC SECP384R1. It may use it for a specific FLIC manifest or a set of manifests or for a time period. It will publish it under /publisher/elsewhere/<ID(WPK)> as an object that has the WSP wrapped under GPK using RSA-OAEP (see RsaKeyWrap() below). The Content Object also identifies the {ID(GPK), GroupKeyLocator}, where GroupKeyLocator is, for example, /key_manager/somewhere.

To generate a data key (DK) to encrypt a manifest, the publisher uses a 1-sided ephemeral Diffie-Hellman key exchange. The ECDHE uses WPK public key and the secret key from an ephemeral key pair EPK/ESK to create a shared master secret then uses HKDF-SHA256 to derive a 256-bit AES key for DK. Part of the KDF input is the KeyNum used to identify the particular DK. This allows the publisher to derive multiple DKs from the same master secret wrapped in the root manifest.

If WPK/WSK are an RSA key pair, then generate a random master secret and use RSA-ENC(WPK, master_secret, RSA-OAEP) instead of the ECDHE method.

In the root manifest, the publisher includes {ID(WPK), WrapKeyPrefix, WrappedKey}. Using the above examples, WrapKeyPrefix is /publisher/elsewhere. WrappedKey = {KeyNum, kex_msg}, where kex_msg is part of the output of EccKeyWrap(), and is the pair {curve, EPK} signed under WSK. The rest of the manifest then looks like a PresharedKey encryption. Note that WrappedKey is not actually encrypted, it is an ECDHE offer to anyone with WSK.

In summary:

`/key_manager/somewhere/<group_name>/<version>` => Link to `/key_manager/somewhere/<ID(GPK)>` namespace

`/key_manager/somewhere/<ID(GPK)>/<ID(UPK)>` => Content Object with RsaKeyWrap(UPK, GSK) signed by KM

`/publisher/elsewhere/<ID(WPK)>` => Content Object with RsaKeyWrap(GPK, WSK) signed by Publisher

(master_secret, wrapped_key) = EccKeyWrap(WSK, WPK)

key_num = sequence number associated with WSK, or large enough random number

dk = KDF(master_secret, 'keynum' || net_byte_order(key_num))

PresharedKeyCtx = {key_num, IV, mode}, IV = AES VI [see NIST], mode = aes-gcm-128, aes-gcm-256

Root Manifest : {ID(WPK), WrapKeyPrefix, wrapped_key, PresharedKeyCtx} signed by Publisher

Other Manifest: {PresharedKeyCtx}

[Ateniese] G. Ateniese, K. Fu, M. Green, and S. Hohenberger, "Improved proxy re-encryption schemes with applications to secure distributed storage," ACM Transactions on Information and System Security (TISSEC), vol. 9, no. 1, pp. 1--30, 2006.

[Wang] Wang, Qiang, Wenchao Li, and Zhiguang Qin. "Proxy Re-Encryption in Access Control Framework of Information-Centric Networks." IEEE Access 7 (2019): 48417-48429.

==========

Definitions:

-   Root Manifest : the top-level named, signed manifest with one pointer to the Top Manifest
-   Top Manifest : hash-named manifest that branches out to full manifest tree of Internal and Leaf manifest nodes
-   Internal node : has both direct and indirect pointers
-   Leaf node : has only direct pointers
-   DK : data key (a symmetric AES key)
-   WK: wrapping key (a symmetric AES key)
-   KM : Key Manager (could be the publisher itself)
-   KDF : Key derivation function, taken as HKDF-SHA256
-   GPK/GSK : Group (public, secret) key. Long-term group keys.
-   UPK/USK : User (public, secret) key. Owned by each user.
-   WPK/WSK : Wrapping key, used for specific manifests or sets of manifests.
-   ID(.) : Key Id function (i.e. SHA256)
-   AES-KWP(key, data) : AES Key Wrap with Padding [rfc5649]
-   AES-KUP(key, data) : AES Key Unwrap with Padding [rfc5649]
-   RSA-ENC(pk, data, padding) : RSA encryption under public key PK with specified padding
-   RSA-DEC(sk, data, padding) : RSA decryption under secret key SK
-   C(1e,1s) - NIST ECC algorithm for 1 ephemeral key 1 secret key.
-   C(1e, 1s, ECC CDH) : NIST algorithm for C(1e, 1s) using ECC co-factor DH [NIST SP 800-56A Rev. 3 Sec 6.2.2.2].
-   ECC-KEYGEN(curve) : [NIST SP 800-56A Rev. 3 Sec 5.6.1.2].
-   ECC-CDH(curve, sk, pk) : [NIST SP 800-56A Rev. 3 Sec 5.7.1.2].
-   ECDHE : Elliptic Curve Diffie-Hellman Ephemeral Key exchange [rfc4492]

## Secret Key Wrapping using RSA

```bash
RsaKeyWrap(PK, data)
	WK = AESKeyGen(256)
	ek = RSA-ENC(PK, WK, RSA-OAEP)
	c = AES-KWP(WK, data)
	return (ek || c)
```

```bash
RsaKeyUnwrap(SK, (ek || c))
	WK = RSA-DEC(SK, ek, RSA-OAEP)
	data = AES-KUP(WK, c)
	return data
```

## Secret Sharing using ECC

```bash
EccKeyOffer(WSK, WPK)
	# Generate ephemeral keys
	(epk, esk) = ECC-KEYGEN(SECP384R1)
	z = ECDHE(WPK, esk)
	dk = KDF(z, 'derived dk')
	kex_msg = ECDSA(WSK, (SECP384R1, epk))
	# kex_msg should be RSA signed by the publisher too
	return (dk, kex_msg)
```

```bash
EccKeyAccept(WSK, kex_msg)
	Verify kex_msg signature with WPK
	Verify kex_msg curve is same as WSK
	Extract epk from kex_msg
	z = ECDHE(epk, WSK)
	dk = KDF(z, 'derived dk')
	return dk
```

## Group Key Distribution:

-   The KM holds GSK/GPK and all UPKs
-   /key_manager.org/prefix/<ID(GPK)>/<ID(UPK)>

-   Names a Content / Data object that holds an wrapped RSA secret key
-   Payload = RsaKeyWrap(UPK, GSK)
-   Signed by KM

-   Encrypted Objects

-   Publisher has a PSK/PPK (publisher public/secret key) and is a member of GPK
-   Publisher request an encryption wrapper from the KM under a GPK
-   KM generates WSK/WPK, such as ECC keys (e.g. SECP384R1)
-   KM returns RsaKeyWrap(PPK, WSK)
-   Publisher publishes session key

-   /publisher.org/elsewhere/<ID(GPK)>/<ID(WPK)>

-   Names a content object with RsaKeyWrap(GPK, WSK)
-   Signed by publisher

-   Publisher generates a DK and WrappedKey

-   (dk, kex_msg) = ECKeyWrap(WSK)

-   Encrypt the object using dk.

1) Root To Preshared

The Root manifest has a KeyWrapContext that resolves to a preshared key. The Top Manifest and rest of the tree is encoded as PresharedKey.

``` bash
KeyWrapContext = KeyId KeyLocator 1*WrappedKey
KeyId = HashValue ; hash of the KDK
```

... to be continued ...


