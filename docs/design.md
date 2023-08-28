# Design

This document will give a description of how the recert tool works, along with
some background about OpenShift, cryptography and PKI (Public Key
Infrastructure) required to understand and develop code for this tool.

It is rather verbose and covers very basic topics, so feel free to skip some
parts that are probably already obvious to you, or read them anyway as a
refresher.

# Background

## OCP clusters

During installation of OCP clusters, many cryptographic objects get generated
and placed in various locations in the filesystem and the cluster's etcd
database. (the etcd database is also technically inside the filesystem, but
requires an etcd instance to reasonably access the information within it, so
it's mentioned and treated distinctly in this document and tool code).

These cryptographic objects, which include certificates, private keys, public
keys, and JWTs are accessed and used by the various processes running inside
the cluster to communicate securely among themselves, and also to communicate
securely with entities outside the cluster.

For example, in order for the kube-apiserver container to communicate securely
with the etcd container, it uses those cryptographic objects to enable this
secure communication channel. Similarly, the certificates and keys you can find
inside a typical admin `kubeconfig` file allow tools like `oc` to make sure
they're securely communicating with the cluster's actual kube-apiserver, and
not an impostor. They also allow the kube-apiserver to make sure it's talking
with a real admin client, and not someone else trying to break into the
cluster.

Some cryptographic objects (private keys, JWTs) are secret. Only select
processes / users should have access them. Leaking those secrets could
compromise the security of the cluster. Other cryptographic objects (public
keys, certificates) are usually associated with objects that are secret, but
they themselves could be publicly advertised / be accessible without
compromising the security of the cluster.

Inspecting the filesystem of an OCP cluster, we'll find two kinds of
cryptographic objects:

1) Cryptographic objects which have been generated especially for the cluster,
during its installation process or during normal operation of the cluster. They
are unique to the cluster and cannot be found anywhere else.

2) Cryptographic objects handed down to the cluster that it might need for
purposes such as securely accessing websites on the Internet. These include
certificates identifying well known Internet CAs. You can find these
certificates in every standard operating system installation, RHCOS included.

Only the first kind of cryptographic objects are of interest to us.

### Image based installation / upgrade

A snapshot (i.e. Disk image) of an already installed, operational cluster may
be taken. One can imagine then using this snapshot to quickly spin up new
clusters ("quick" because the cluster does not have to be re-installed,
everything is already in place for it to be immediately operational). We call
this image based "installation". This is also useful for performing fast
upgrades of existing clusters where you backup user data, perform an image
based "installation", and restore user data on top.

One obstacle in attempting spin up multiple clusters from the same image is the
fact that those clusters now share all of their cryptographic objects. This is
bad because as mentioned above, some of these cryptographic objects must remain
secret, with limited access only to select processes.

One example that demonstrates an obvious way in which this compromises the
security of the cluster is that an admin `kubeconfig` used by one such cluster,
would work and could be used to administer all clusters which have been spun up
from the same image!

The aim of the recert tool is to solve this problem of shared cryptography. In
other words, allow the use of image based installation, while avoiding shared
cryptography. Of course there are many additional issues to solve with image
based installation, but this is one of them and on which we will focus.

## Symmetric Cryptography

Symmetric cryptography is cryptography in which both sides of the conversation
use the exact same key to communicate. The key can be used for both encryption
of a message, and also for decryption / verification of a message.

While symmetric cryptography is heavily in use inside OCP clusters, all keys
used for such cryptography are ephemeral and are never really persisted to
disk. Therefore this type of cryptography is of no concern to recert.

One big limit of symmetric cryptography is that the key exchange must happen in
secret. Anyone eavesdropping on the key exchange can see the secret key and use
it to decrypt all further communication.

Symmetric cryptography can be performed very fast by computers.

## Asymmetric Cryptography

In asymmetric cryptography, two keys, linked in a particular mathematical way,
are generated - one called a "public key" and another called a "private key".

### Asymmetric encryption / decryption

Their mathematical relationship is such that the public key can be used to
encrypt messages, but even though the public key can encrypt messages, it
cannot be used to decrypt them. In other words, if you encrypt a message using
a public key, even you, the person or program that performed this encryption,
cannot undo it to recover the plaintext (plaintext is a general cryptography
term used to refer to the plain, unencrypted message before it has been
encrypted, or after it has been successfully decrypted). The private key on the
other hand can be used decrypt all messages that have been encrypted with the
public key mathematically associated with it.

Given a particular public key, there is no way to know what the private key
associated with it is. This is not true the other way around. You can easily
derive the public key from the private key.

One big advantage of public key cryptography is that I can generate a
public-private key pair, and loudly advertise my public key to everybody - as
it's not secret (hence the name, "public"). It's not a secret because it cannot
be used to decrypt messages. Then everybody who knows my public key can use it
to encrypt messages, and send them to me, even through insecure channels.
Nobody in the world can then decrypt those public-key encrypted messages, even
people who know my public key, even the very people who encrypted the messages.
Only me, who holds the associated private key in secret, can decrypt messages
encrypted by my public key.

This means that a large corporation, say Google, can have their public key
publicly known by everybody. Then everyone in the world can use the well known
Google public key to encrypt traffic sent to Google, and only Google would be
able to decrypt this traffic.

One big disadvantage of public key cryptography is that the encryption /
decryption operations using it are very slow. This means that it can only
practically be used to encrypt small amounts of data. But this is not a big
deal, as you can simply use someone's advertised public key to encrypt a
standard symmetric cryptography key (which is typically less than a hundred
bytes), send the encrypted symmetric key to the recipient through insecure
channels (remember, eavesdroppers can't do anything with this encrypted key),
and now the recipient can use their secret associated private key to decrypt
the encrypted symmetric key to discover the symmetric key. Now both the sender
and the recipient know the same symmetric key that they can use to communicate
through fast symmetric cryptography - in essence they have leveraged asymmetric
cryptography in order to exchange a symmetric key over an insecure channel.

The only thing needed before that exchange could happen was for the sender to
know what the recipient's public key is in advance. Managing this knowledge of
which recipient owns which public key is a not a trivial problem to solve, and
on the web it is solved by something called Public Key Infrastructure (PKI),
which this document will elaborate on later.

### Asymmetric digital signing

Private and public keys can be used for more than just encryption and
decryption - they can be used for something called signing (symmetric
cryptography can also be used for signing, but this irrelevant for this
document and will not be discussed).

Signing is when you take a piece of data, for example `I vote Foo for
president!`, and you perform some special mathematical operation on that piece
of data using your private key. The result of that mathematical operation is
another piece of unrecognizable data called a "signature".

You can then advertise this signature. Anyone who knows your public key can use
your public key to turn this signature back into the original piece of data: `I
vote Foo for president!`. They can also know for sure that you, the holder
of the private key associated with the known public key, has surely created
this signature yourself. 

No one else in the world can create a signature that successfully transforms
without error into a valid piece of data when operated on with your public key.
(although of course if you were uncareful and somehow let your private key
leak, none of this is true).

And so, in a way, you, the only person in the world who knows your private key,
have "vouched" for the string `I vote Foo for president!` by signing it with
your private key. And anyone in the world who knows your public key can safely
assume that you have vouched for `I vote Foo for president!`, after verifying
the signature with your public key.

The usefulness of such digital signatures will be made apparent later in the
next section.

Another thing worth mentioning about digital signatures is that just like
asymmetric encryption/decryption, they are typically very expensive to compute
on large amounts of data. But just like with encryption/decryption - there is a
simple solution. Take the large amount of data you want to sign, compute a
cryptographic hash of the data - then just sign the hash. In essence by signing
the hash, you have signed the data "by proxy". This is because (good)
cryptographic hashes guarantee that no one could feasibly come up with a
different piece of data that results in the same hash. Now to present the data
you have signed, you can simply deliver the plain data along with the
signature. Anyone who wants to verify that the data has been signed by you can
simply compute the hash of the data, operate on the signature with your public
key to get back the underlying hash that you have signed, and compare this hash
to the hash they have just computed on the data to make sure they're the same.
Hashes are usually much much faster than signature algorithms, so the problem
is solved.

There are multiple types of asymmetric cryptography, famously RSA but also EC
and Ed.

## Public Key Infrastructure

Imagine you want to access `https://www.google.com/search?q=foo` on your
browser. You don't want your ISP, which can easily see all packets going back
and forth between you and Google's servers, to know you're searching for `foo`.

So you use `https` and not `http`, which delivers HTTP over TLS to make things
secure. But what actually happens behind the scenes to make this communication
secure?

As mentioned before, in order to for you to securely send Google messages,
without allowing eavesdroppers to understand those messages, either both you
and Google need to share a secret symmetrical encryption key, or you need to
know Google's asymmetric public key.

The former option is impractical - Google cannot possibly maintain a record of
symmetric keys between it and every device / person in the world.

The second option is a bit more practical - Google is a famous company, maybe
your browser already comes pre-installed with knowledge of Google's famous
public key, and so it can use that key to exchange a temporary symmetric key
with Google while your ISP eavesdropping on the conversation being none the
wiser.

But of course you like browsing into websites other than Google, for example,
the website for a local newspaper. Of course we also cannot expect browsers to
come pre-installed with a list of public keys of all websites in the world, and
so we need to figure out a way for your browser to somehow discover your local
newspaper's website's public key.

Similarly to how your browser doesn't have the public key for your local
newspaper, it also doesn't have the public key for Google.

So how does it work?

You cannot simply send a message to Google's servers asking for their public
key, as your ISP can easily intercept this message, and send you their own
public key pretending it's Google's. You would then use this fake public key to
encrypt traffic and send the encrypted traffic to Google, only for your ISP to
again intercept this traffic, easily decrypting it because it has been
encrypted with the ISP's own public key (which you thought was Google's), then
with this decrypted traffic the ISP can act as a proxy between you and Google,
pretending that everything is encrypted, while in reality the ISP can both see
and modify all the traffic.

In other words, you need some way to ask Google for their public key, and then
once you receive their public key, you need some way to know that this public
key actually belongs to Google, and wasn't just made up by your ISP.

This is where digital signatures come into play. Your browser may not know
Google's public key, but it does does know the public keys of a bunch of
entities it fully trusts called "Certificate Authorities" (CAs).

In simple terms, CAs are organizations which, upon request initiated by the
administrators of a website (e.g. Google), associate that website with a public
key. And they make extra sure that whoever is operating this website actually
owns the private keys associated with this public key. There are many ways CAs
use to get a proof of that. One of them is a protocol called ACME, the details
of which are out of scope for this document, but in general may include special
DNS records with a particular challenge string, or placing a challenge string
inside the website's HTML tags.

Once a CA has received enough proof from a website that they are actually who
they say they are, they will issue to them something called a "Certificate".
Practically all certificates today follow a standard format called X.509, and
in "pseudotext" they look something like this:

```
    ______________________________________________________________________________
    |                                                                             |
    | I, certificate authority Foo, hereby confirm that the public key XYZ, using |
    | algorithm RSA, belongs to the website with domain bar.example.com.          |
    |                                                                             |
    | This confirmation is valid beginning January 01, 1970 and is no longer      |
    | valid past January 01, 1971.                                                |
    |                                                                             |
    | Yours truly, Foo.                                                           |
    |                                                                             |
    | Signed using ECDSA with a SHA256 hash                                       |
    |                                                                             |
    | <signature bytes>                                                           |
    |                                                                             |
    ______________________________________________________________________________
```

The signature bytes at the end are the result of the Foo CA using its private
key to sign a SHA256 hash which has been computed on the rest of the
certificate's bytes that came before.

The website `bar.example.com` can now present this certificate to anyone who
tries to visit it.

In essence a certificate is a signed statement by a CA that a particular public
is truly associated with a particular subject (on the web, that subject is
usually a domain name).

When you use a browser to visit the `https://bar.example.com/` website, your
browser will immediately receive this certificate. Because your browser trusts
the Foo CA (and many other CAs), and comes pre-installed with those CA's public
keys, your browser can validate and inspect this presented certificate as
follows:

* It will see that the certificate has been issued to `bar.example.com`, and so
it will ensure this domain actually corresponds to the website that you were
trying to visit when this certificate was presented to you

* It will use the dates noted on the certificate to ensure that the certificate
is still valid, and not expired.

* It will see that the certificate says it was issued by the Foo CA. So it will
grab the Foo CA's public key from all the keys it has pre-installed.

* It will compute a SHA256 hash (as stated in the certificate) on the entire certificate,
excluding the signature bytes at the end

* It will use Foo CA's public key to operate on the signature bytes, and if the
public key truly matches the private key that the Foo CA used to create this
signature, this operation will result in the hash that was signed by Foo CA.

* It will compare the respective hashes from the previous steps to make sure they're equal

Because the Foo CA (and all other CAs) work really hard to keep their private
keys ultra secret and secure, your browser now knows with very high confidence
that the Foo CA, which it trusts, vouch that whoever's operating
`bar.example.com` truly owns the private key behind the XYZ public key.

Now that your browser knows that the XYZ public key is truly associated with
`bar.example.com`, and is not some fake public key injected by your ISP, it can
use it to exchange symmetric keys which will be used both by your browser and
by `bar.example.com` to encrypt the HTTP traffic, thus allowing you to securely
browse `bar.example.com` with high confidence that nobody is snooping or
modifying this traffic.

So just by knowing the public key of a few CAs, you can securely visit any
website in the world without ever exchanging any kind of keys with them in
advance.

## Certificate chains

Earlier when I said your browser comes with the public keys of a few CAs
pre-installed, it was a slight over simplification. In reality, those "public
keys" come in the form of yet another certificate, but unlike the certificate
above, this certificate is "self-signed", and not issued to any particular domain,
but instead looks, in "pseudotext", something like this:

```
    ______________________________________________________________________________
    |                                                                             |
    | I, certificate authority Foo, hereby confirm that I, myself, use public     |
    | key ABC with algorithm ECDSA.                                               |
    |                                                                             |
    | This confirmation is valid beginning January 01, 1970 and is no longer      |
    | valid past January 01, 1991.                                                |
    |                                                                             |
    | Yours truly, Foo.                                                           |
    |                                                                             |
    | Signed using ECDSA with a SHA256 hash                                       |
    |                                                                             |
    | <signature bytes>                                                           |
    |                                                                             |
    ______________________________________________________________________________
```

This is often gets called a "root CA", "CA certificate" or "self-signed
certificate". The signature bytes at the end are the result of signing the hash
of the certificate with the private key corresponding to the ABC public key
mentioned in the certificate itself. Of course this certificate is not very
convincing, as anyone could make a certificate that signed itself (as long as
they're not constrained in choosing the public key). And that's why root
certificates such as this have to be explicitly trusted.

All certificates actually have an "issuer" field that tells you which
certificate signed them, and a "subject" field, which tells you who the
certificate was issued for. For non-root certificates, the issuer would usually
be a root-certificate and the subject would usually be a domain name. For
root-certificates, the "issuer" and "subject" fields are both equal. Their
value is simply the name of the CA. 

Once you trust a bunch of root certificates, any time you're presented with a
non-root certificate, you can check which other certificate issued (signed)
that non-root certificate, and if that non-root certificate has been signed by
a root certificate which you already trust, then you can also trust that the
non-root certificate is telling the truth (since you know and trust your root
CAs to only sign certificates which tell the truth).

In fact, you can go further, and a non-root certificate may sign yet another
certificate, in essence creating a "chain" of certificates, all leading back to
a particular root certificate. And if you trust the root certificate, then you
trust all certificates in that chain.

Worth noting that X.509 also has a special field that states whether a
certificate is allowed to sign other certificates. This way CAs can issue a
certificate, but specify that this certificate cannot be used to issue further
certificates. This would be done to certificates issued to a website to ensure
they're not then used to issue fake certificates for other websites. If they
tried, your browser would notice the special field that says they're not
allowed to issue certificates, and would consider the certificates signed by
them as invalid.

## Cryptographic objects encoding

Cryptographic objects are usually encoded through multiple layers of encoding,
which this document will try to give a rough overview of.

### ASN.1

Abstract Syntax Notation One (ASN.1) is a language for defining logical data
structures, which can then later be serialized in a cross platform way.

It defines multiple primitives such as integers (arbitrary size), sequences
(lists of other primitives), messages (structs), strings, booleans, and so
forth.

ASN.1 is used to describe the structure of public keys, certificates and
private keys.

### XER/BER/DER

ASN.1 structures, which are only logical, can be serialized in many different
ways. One example of such encoding is XER (XML Encoding Rules), which encodes
these structures using textual XML.

Another example of such encoding is BER (Basic Encoding Rules), which defines
the rules of how to serialize ASN.1 structures into binary bytes.

The encoding used for cryptographic purposes is DER (Distinguished Encoding
Rules), which is basically the same as BER, except it's more restrictive,
removing any sort of ambiguity / inconsistency, by only allowing a single way
to serialize a particular struct into bytes. For example, in BER, you could
serialize a boolean as 0 for false or 1-255 for true. In DER, a boolean is
encoded as either 0 for false or 1 for true. This consistency is important
because with cryptography every bit has to be right and could make a huge
difference.

### PEM

Since DER is a binary encoding, which can't be comfortably managed in text
(e.g. emails, text editors, terminals, etc), it's usually further encoded into
textual form using the PEM encoding format. PEM stands for Privacy-Enhanced
Mail, which are standards which were never really adopted, but the textual
encoding which they defined lived on to be very popular.

PEM encoding takes a tag (title) and DER bytes as input, encodes the bytes into
base64, splits it into lines of 64 letters, and wraps it up with a header and
footer which contain the given tag. Here is an example of an RSA key encoded
as PEM with the tag "PUBLIC KEY":

```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0H2Mi4U+Ay5xuPzQhTpe
BvDlKaS9x0HmYDyHt3wzmQUIgtaVUOClyJA92HwNmkfyAvPbNpk79kzbhMLuEZHG
9EWxvCzZ8NJNACeSDAALJs6Jt/qVnCKFobhBghVTlaDwU5kNdGliKEB59yO9v9K8
CVoNLjUvRUBRoMeqDubXd786h8v9o6dCXQk9dYEB7efxzLfz+tMazLnJPVgZEHxx
EPxKnHkKoiSn0MrDyIIh6zC46NetRC9NgKtrfwFWA76fWxBz+PeaObLAktEUkXr4
YDcybMfXSn+eBpOd+Br4dJuYU0x7wA17E1mdJrc5jDkRlU4MrKQ9rCC/jDqaX/0P
l2LJsdkKwf3ApEKoKjJcqQAwA37pHjrCwia85WvKaoXQwOZQMcUlxTJNn6ztKc3R
7/UXrza/BZO/QNw+Z2U7YgWvDugPdALkOlQ9Q+uPEJyZRhbj996+0ic6aYN/nKN+
cO81KzaAQ46Fc9kR8aUV7mv1E+B4ETeNb3+j1XMVCQggFgaWz7ePm2I06FqAdwIz
p0xeIT11i3UdobbC7581yCd3AsYE1xrY6OvNTF9G3RW/1cQLDb9bM31TdPTjvUEa
3B0HqmUWOddtcFYztc/uOeqmCheO7hoVIJWVoDnzH84eo8fmergUEvZZRkpNZCYQ
i/j5zna1bGu8BuHeMOn4hwUCAwEAAQ==
-----END PUBLIC KEY-----
```

Multiple PEM encoded objects may be concatenated, one after the other, to form
a PEM "bundle".

### Certificates

The X.509 RFC 5280 standard defines, among other things, the ASN.1 structures
used to represent certificates.

```
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }
```

Certificates are usually encoded into DER and presented as PEM with the tag
"CERTIFICATE".

A certificate is made up of 3 main fields - the `tbsCertificate`, which is a
struct. TBS stands for "To-be-signed". This is the main part of the certificate
and contains pretty much all the details of the certificate itself. We will
dive into this struct later.

The next field in the certificate is the signature algorithm, which is an
identifier which tells you both which hash algorithm was used to hash the
TBSCertificate, and the signature algorithm that was used to then sign the
computed hash.

The signed hash is then placed inside the next field, the signature value.

(Since tbsCertificate is in ASN.1, which you of-course cannot compute the hash
of, the TBSCertificate is first serialized using DER into bytes, and the hash
is computed on those DER bytes).

The TBSCertificate struct is defined as follows:

```
   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
        extensions      [3]  EXPLICIT Extensions OPTIONAL }
```

The `signature` field is an identifier identical to the `signatureAlgorithm`
field we mentioned above.

The `validity` is a struct of type `Validity` which defines the beginning of expiration
times of the certificate:

```
Validity ::= SEQUENCE {
     notBefore      Time,
     notAfter       Time  }
```

The `issuer` field identifies the CA that issued the certificate, while the
`subject` field identifies who the certificate was issued to. They both have
type `Name` which is a complex struct we won't get into, but essentially it's a
list of types (e.g. name, surname, initials, commonName (aka CN)) and their
corresponding values.

Historically, certificates issued for particular domain names wrote down the
domain name to which the certificate were issued for inside `subject`
`commonName` entries.

There's a shift towards deprecating this method of specifying the domain names,
these days it's recommended to use the less ambiguous Subject Alternative Name
(SAN) extension (see the `extensions` field at the end of the `TBSCertificate`
struct, which allows for additional extensions to certificates).

The unique ID fields are rarely ever used.

The `subjectPublicKeyInfo` field contains the actual public key associated with
the subject of the certificate:

```
SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
```

The `algorithm` field specifies what kind of public key it is (e.g. RSA), and the
`subjectPublicKey` is the DER encoded public key.

### Public keys

Public keys are usually just a bunch of very large numbers. For example, in
RSA, a public key is a combination of 2 numbers, a modulus (big number) and an
exponent. 

According to RFC-8071 (PKCS #1), in ASN.1 RSA public keys are represented with
the following ASN.1 struct definition:

```
         RSAPublicKey ::= SEQUENCE {
             modulus           INTEGER,  -- n
             publicExponent    INTEGER   -- e
         }
```

In other words, they're simply a sequence of two numbers.

We usually find public keys in 2 forms:

#### Certificate public key

This is a public key placed inside the subjectPublicKeyInfo field of the
certificate.

#### PKCS#1

These are public keys encoded according to the PKCS#1 format, which only
applies to RSA.

Their PEM tag is "RSA PUBLIC KEY", and their contents are simply the DER
encoded RSAPublicKey struct above.

### SPKI 

These are public keys encoded similarly to how they're included in
certificates, which supports many different key algorithms.

Their PEM tag is simply "PUBLIC KEY", and their contents are actually just the
SubjectPublicKeyInfo (mentioned above. sometimes shortened to SPKI) struct
(taken from the X.509 standard) encoded as DER.

As you can see, this struct also contains the algorithm identifier, and so it
can be used to describe keys of other algorithms.

It may look to you like OpenShift is using the PKCS#1 format for its public
keys, because if you look at an RSA public key PEM file from OpenShift, you'll
see "RSA PUBLIC KEY" in the PEM tag, but this is actually wrong, as internally,
if you parse the DER bytes, you'll see that it's actually following the SPKI
structure and not the PKCS#1 structure.

### Private keys

Private keys are encoded similarly to public keys. We find them in 3 forms:

#### PKCS#1

These are private keys encoded according to the PKCS#1 format, which only
applies to RSA.

Their PEM tag is "RSA PRIVATE KEY", and their contents are simply the DER
encoded struct from the PKCS#1 standard:

```
         RSAPrivateKey ::= SEQUENCE {
             version           Version,
             modulus           INTEGER,  -- n
             publicExponent    INTEGER,  -- e
             privateExponent   INTEGER,  -- d
             prime1            INTEGER,  -- p
             prime2            INTEGER,  -- q
             exponent1         INTEGER,  -- d mod (p-1)
             exponent2         INTEGER,  -- d mod (q-1)
             coefficient       INTEGER,  -- (inverse of q) mod p
             otherPrimeInfos   OtherPrimeInfos OPTIONAL
         }
```

#### RFC-5915

These are EC private keys encoded according to the format defined in RFC 5915,
which only applies to EC keys.

Their PEM tag is "EC PRIVATE KEY", and their contents are simply the DER
encoded struct from the RFC 5915:

```
         ECPrivateKey ::= SEQUENCE {
             version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
             privateKey     OCTET STRING,
             parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
             publicKey  [1] BIT STRING OPTIONAL
         }
```

#### PKCS#8

These are private keys encoded according to PKCS#8 which supports many
different key algorithms. 

Their PEM tag is "PRIVATE KEY". You can read about their ASN.1 structure
[here](https://datatracker.ietf.org/doc/html/rfc5208#section-5).

# recert

Now that we understand the background of how certificates and asymmetric
cryptography works, this section will talk about how recert works.

## Context

recert is a CLI utility. It is intended to be ran only a single time,
immediately after you boot a cluster for the first time from an image, before
kubelet starts. As input, recert receives a list of directories and an etcd
endpoint.

The list of directories is where recert will look for cryptographic objects
that it you want it to regenerate. The etcd endpoint is for the cluster's etcd
database, where recert will look for Kubernetes resources that it knows might
contain cryptographic objects.

There are a few other configuration options for recert that you can learn more
about by looking in the `src/cli.rs` file, or by running recert with the `--help`
commandline argument.

## Stages

Once launched, recert operates in multiple distinct stages.

### Stage 1 - Scanning

The first stage is actually finding all the cryptographic objects - recert
looks in both the filesystem and etcd. On the one hand, it doesn't have a list
of known locations of where exactly to find cryptographic objects. On the other
hand, it does look for them in very particular places and doesn't do a complete
blind brute-force search of everything. It's very specialized for OCP clusters
and requires a lot of testing and maintenance to make sure it looks in the
right places and doesn't miss anything.

#### etcd scanning

recert will fetch all etcd values of `secrets`, `configmaps`, `machineconfigs`
and a few other kinds. Since etcd doesn't store YAMLs for most resources, and
instead stores a protobuf binary encoding of the resources, `recert` for now
has to use [ouger](https://github.com/omertuc/ouger/) to convert those
resources from and to YAML (this is usually done by kube-apiserver when you
normally use kubernetes, but with recert we use direct etcd access).

For each kind of resource, `recert` has specialized code to scan it for
cryptographic objects. i.e., recert will not simply brute-force blindly
recursing through the YAML structure to look for cryptographic objects.
Instead, for example, in configmaps recert will loop through the `.data`
section. For secrets, it will look inside the `.data` section while decoding
the values from base64. For machineconfigs, recert will iterate through the
list of files in the storage section of the ignition config, decoding their
dataurl values, and so on.

#### Filesystem scanning

A lot of cryptographic objects reside on the filesystem itself instead of
inside etcd, so recert supports scanning there as well. Currently known
directories of interest for include `/etc/kubernetes`, `/var/lib/kubelet` and
`/etc/machine-config-daemon`.

For every directory given as input, recert will recursively search for files
that have extensions which might indicate the file contains cryptographic
objects. Extensions such as `.crt`, `.pem`, `.key`, `kubeconfig`, etc.

These files are either YAMLs, which require parsing and further scanning,
similar to how we do with `etcd` scanning, or alternatively they might simply
only contain the cryptographic objects themselves in PEM format.

#### Scan results

Every time we encounter a cryptographic object during a scan, we note down
where we found it. The reason for that is that we later, after regenerating the
cryptographic object, have to write it back in where we found it.

We do that using a rather involved `Location` type which encodes where a
cryptographic object was found.

For etcd, that location includes its kind, apiversion, namespace and name. But
that only tells us which etcd resource it was found in. An etcd resource YAML
may contain multiple cryptographic objects. So we also have to note down where
exactly inside the YAML we found it. We do that using [JSON
Pointers](https://datatracker.ietf.org/doc/html/rfc6901), which kinda look like
jq queries. Furthermore, it's not enough to note where we found it, we also
have to note how it was encoded, because later when we write it back, we need
to encode it correctly. e.g. Secrets encode their fields in base64, and
configmaps don't. machineconfigs encode their files in dataurl format.

It actually gets worse - cryptographic objects usually appear in the PEM
format, which usually comes in bundles of many distinct PEM objects, and so we
also have to note the index (i.e. offset) of the discovered object within the
PEM bundle.

If we find a cryptographic object in the filesystem, we simply note down its
path and other information similarly to etcd as explained above.

### Stage 2 - Registration, deduplication

The same cryptographic object may appear in many different locations. When
regenerating certificates, for example, we don't want to treat two certificates
as "different" just because we found them in different locations, we want to
treat them as the same certificate. We only regenerate each cryptographic
object once, then we write it back to *all* the locations we found it in.

To perform deduplication, we take the list of cryptographic objects from the
previous step and we register them into hashmaps where the keys are the
cryptographic objects themselves (not including their location), and the values
are a struct which records all the locations the cryptographic object was found
in, to which we keep adding more and more locations as we go through the list.

### Stage 3 - Relationships

Now that we have a list of "logical" cryptographic objects, as in  they're
"detached" from the locations they were found in through deduplication, before
we can regenerate them, we need to understand how they relate to each other.

Our cryptographic objects may relate in the following ways:

* Every certificate contains a subject public key

* Every certificate might be associated with a private key linked to the
certificate's subject public key

* Every certificate might be associated with a "standalone" public key (one
found outside a certificate) that equals its subject public key

* Every private key might be associated with a "standalone" public key linked
to it

* A certificate may be signed ("issued") by another certificate

* A certificate may be signed ("issued") by itself

This might look something like this:

```


                          _________________
                          |                |
                          |  Certificate   |
                          |  (self signed) |
_____________             | _____________  |
|"Standalone"|   same as  | |            | | linked _____________ 
| public key | <------------- public key ---------->|            |
|____________|            | |____________| |        | private key|
                          |________________|        |____________|
                                 | signed
                                 |
                                 |
                                 |
                                 | signed by
                          _______|_________
                          |                |
                          | Certificate    |
                          |                |
_____________             | _____________  |
|"Standalone"|   same as  | |            | | linked  _____________ 
| public key | <------------- public key ---------->|            |
|____________|            | |____________| |        | private key|
                          |________________|        |____________|


_______________                 _____________ 
| "Standalone" |      linked    |"Standalone"|
| Private key  | <------------->| public key |
|______________|                |____________|

```

To establish how all of our discovered cryptographic relate, we do so in a few
simple steps:

#### Relationships step 1 - Pair certs with private keys

We want to pair every certificate with the private key that is mathematically
linked to the subject public key of the certificate. These are often called
"Cert key pairs".

In recert we do so by iterating over our list of certificates. We take note of
their subject public key, then we iterate over the list of private keys, and
for each private key we derive the public key from it. If the result matches
the public key in the certificate, we pair the certificate with the private
key.

Sometimes this search might yield no results. This is OK. Sometimes
certificates in a cluster have no private key that matches their subject public
key because it gets discarded during installation.

Once we pair a private key with a certificate, we add them as a pair to our
list of cert key pairs.

We also remove the private key from our list of private keys. The reason for
this removal is that some private keys are not associated with any cert, and
instead are used just for signing JWTs, which are another cryptographic object
this document conveniently ignores to keep things simple. We call private keys
not associated with any cert "standalone" private keys. These are the ones
leftover in the list after we're done pairing all other private keys to
certificates.

#### Relationships step 2 - Collect key-cert pair signers

For every cert-key pair we first check whether its cert is self-signed. If it's
not, we need to find which other pair signed it. We do that by iterating over
all other pairs and checking whether they signed our certificate. If it did, we
maintain a pointer called "signer" on the signed pair pointing at its signing
cert.

We do a similar thing for JWTs.

#### Relationships step 3 - Fill signees

Now that every cert-key pair holds a pointer to its signing pair, we do the
reverse - for each pair we iterate over all other pairs and check whether their
"signer" field points at our pair. If it does, we add them to a list called
"signees" which we maintain for every pair.

We do a similar thing for JWTs, but with JWTs we also check the list of
standalone private keys, as usually (basically always) they're signed by
non-cert related keys.

#### Relationships step 4 - Associate standalone public keys

We associate every cert-key pair with any standalone public key that matches
its certificate subject public key (or linked with the pair's private key,
which means the same thing). We also associate standalone private keys with
standalone public keys.

### Stage 3 - Regeneration

Now that we know how all the cryptographic objects relate, we can regenerate
them to have new cryptographic values. We start by regenerating all cert-key
pairs. We must do that from the top down, recursively. For every self-signed
cert-key pair, we must first regenerate it and only after we regenerate it, we
can iterate over its signees and regenerate each one of them (and as part of
that we might further regenerate their own children). This is because child
certificates must be signed with their parent certificate's private key, and so
we must regenerate that parent to know its private key before we can move on to
signing its children.

Regenerating a certificate is done in multiple steps. First, we generate a new
random key public-private key pair using the same algorithm and size as the
original cert (e.g. RSA 4096-bit). Next, we implant this newly generated key in
the `subjectPublicKeyInfo` field of the certificate. Since we have modified the
TBS part of the certificate, its signature is no longer valid (as changing its
content makes its hash change), so we need to update the signature. If the
original certificate was self-signed, we simply use the private key we just
generated for it to re-sign it. If the certificate is not self-signed, we will
instead use the private key that we generated for its parent certificate (this
demonstrates why parents must be regenerated before children).

### Stage 4 - Commit

All of our cryptographic objects have been regenerated, but we've only done this
to their logical representation in our memory. We need to go object by object and
re-write it back to etcd / filesystem, in all the locations we found it. There's not
much else to say about this part, it's pretty straight-forward.

### Stage 5 - OCP postprocessing 

OLM has some annotation which for some reason contains the hash of one of the
certificates, and because we changed the certificate, the hash no longer
matches and so OLM becomes unhappy (and don't reconcile). We have specialized
code to handle this little quirk and re-calculate that hash to make OLM happy.

## Customizations

### Certificate CN/SAN replace

recert accepts as input a list of domain names which it will look for in the
subject CN / issuer CN / SAN extension fields of certificates, and a list of domain
names which it should replace them with.

This allows you to change the dummy cluster domain names baked into the
certificates of the image you're trying regenerate the cryptography of with a new
domain that you want your new cluster to have.

The reason recert must provide this functionality, as opposed to doing it after
the fact, is because you cannot simply change the domain name in certificates,
as it will invalidate the signature of the certificate (hash change). Because
recert is already collecting / re-signing certs, it's in a good spot to make
this change.

### Cluster Rename

recert accepts as input a new cluster name and new base domain. This will cause
an extra step during the OCP postprocessing stage which scans known locations
in OCP clusters (in both the filesystem and etcd) where the domain name of a
cluster appears in, and modifies them to have a new domain name. This is not
changing any cryptographic objects, simply known OCP fields which happen to
contain the domain. This code was added to recert for convenience (since it
already knows how to access etcd directly and modify it), and doesn't really
have anything to do with the rest of the tool.

### Use Key

You can provide re-cert with a private key and a CN. When re-cert generates a
cert-key pair, and that certificate has a subject CN field which matches the
given CN field, recert will use your given private key instead of randomly
generating a new one. This is useful in image-based upgrades where you want the
old kubeconfig from the pre-upgrade cluster to keep working.

### Use cert

Similar to use key, but the user provides us with a cert instead. When re-cert
generates a cert-key pair, and that certificate has a subject CN field which
matches the given certificate's subject CN field, recert will simply use the
user provided cert instead of generating a new one. This is also useful for
image-based upgrades where you want the old kubeconfig from the pre-upgrade
cluster to keep working, but you don't have access to the private key that was
used to sign the kubeconfig client cert, which is the case in OpenShift - that
key gets discarded during installation.

## Optimizations

### etcd cache

During the Commit stage mentioned above, we would do many writes to etcd. It's
very slow to go through ouger and etcd for each one, so instead we maintain an
in-memory cache of all etcd YAMLs, and all writes actually happen in memory.

In the end, we simply commit that cache back to etcd. This essentially batches
all the etcd writes of the same YAML into a single operation.

### Early RSA key generation

Generating RSA keys is very slow, so in order to save time, we pre-generate a
pool of RSA keys (a very CPU intensive task) at the same time that we scan etcd
/ the filesystem (a very IO-bound task). Later when we actually need those keys
for regenerating cryptographic objects, we simply draw from the pool instead
of calculating new ones.

### async concurrency

A lot of our code is mostly IO-bound and a lot of different tasks can happen
concurrently, but creating a thread for each task is impractical since there's
so many of them, and so we leverage async Rust (specifically tokio) to
orchestrate those tasks.

# FIPS compliance

recert should delegate all cryptographic work to OpenSSL to ensure FIPS
compliance. Calculating hashes, generating keys, signing certificates, signing
JWTs - it must be done with OpenSSL. At first we had FIPS violation concerns
about the way we modify raw certs - but we received assurance that since
certificates are just encoding+metadata for cryptographic keys, they are of no
concern to FIPS. So as long as the keys/signatures themselves are created with
OpenSSL, the certificate editing can be done with Rust.
