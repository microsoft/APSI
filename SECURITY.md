<!-- BEGIN MICROSOFT SECURITY.MD V1.0.0 BLOCK -->

## Security

Microsoft takes the security of our software products and services seriously, which
includes all source code repositories in our GitHub organizations.

**Please do not report security vulnerabilities through public GitHub issues.**

For security reporting information, locations, contact information, and policies,
please review the latest guidance for Microsoft repositories at
[https://aka.ms/SECURITY.md](https://aka.ms/SECURITY.md).

<!-- END MICROSOFT SECURITY.MD BLOCK -->

## Deploying APSI Securely

APSI is a library for computing a private set intersection, not a complete secure channel. It
protects the *contents* of both parties' sets from each other; it does not protect the exchange
itself. Deployments must supply the rest.

The following are properties of APSI as shipped, not defects to be worked around in a later
release. They are described in more detail under
[Trust Model](README.md#trust-model) in the README.

**Run APSI over an authenticated channel.** APSI applies no authentication of its own and puts no
integrity protection on the wire. Any party able to write to a receiver's connection can make it
report an arbitrary set of matches, using only the publicly known protocol parameters &ndash; no
key material, and no involvement from the real sender. The receiver cannot detect this by
inspecting what it receives. The `network::ZMQChannel` implementations used by the example
applications are unauthenticated plaintext and are suitable for a trusted network or a local
experiment; anything else needs a tunnel (TLS, mTLS, WireGuard, SSH) or a transport of your own
supplied through `network::StreamChannel`.

**Treat the right to query as a privilege.** A peer permitted to make repeated queries can extract
the sender's label data, because the sender must evaluate encrypted inputs it has no way to check.
APSI does not rate-limit, meter, or attribute queries, and has no authenticated notion of a peer to
attribute them to. A deployment serving labels should bound query volume per peer above APSI.

**The OPRF endpoint answers anyone.** It applies no authentication and no cap, and it answers for
items that are not in the sender's set. Its access control is load-bearing for label
confidentiality and should be treated as such.

**Some metadata is visible on the wire.** Request sizes reveal the receiver's exact query-set size.
The sender's set size is not treated as secret by the design.

**A serialized `SenderDB` is key material.** It carries the OPRF key alongside the data that key
protects, and the example sender writes the key into the same file. Anyone holding that file can
decrypt labels and test membership offline. Store and transfer it accordingly.

**Labels have no integrity protection.** Label encryption is unauthenticated, so a party on the
connection can alter a delivered label undetectably. An authenticated channel is what prevents
this today.
