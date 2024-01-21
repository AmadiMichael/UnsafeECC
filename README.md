# Unsafe ECC

This collection comprises proof of concept demonstrations and explanatory content on vulnerabilities associated with Elliptic Curve Cryptography (ECC). Instead of merely advising against certain practices with a generic warning, it goes further to illustrate precisely how vulnerabilities can be exploited and outlines the derivation of the underlying formulas.

## Contents

- **Nonce Reuse**: Explores the scenario where, given two signatures (`s1` and `s2`) of messages (`m1` and `m2`) respectively, signed by a private key (`p`) with the corresponding public key (`q`), a malicious actor can calculate and obtain `p` using only `s1`, `s2`, `m1`, and `m2`.
- **Nonce Leak**: Examines the situation where, with a signature `s` of message `m` signed using nonce `k` by a private key (`p`) with the corresponding public key (`q`), a malicious actor can calculate and obtain `p` using just `s`, `m`, and `k`.
- **Fake Signatures**: Explores how, with knowledge of a private key (`p`) and its corresponding public key (`q`), a malicious actor can generate a signature and message pair that resolves to `q` without the exploiter needing to know or have access to `p`.
- **Signature Malleability**: Covers the process wherein, given a signature (`v`, `r`, and `s`) of a message (`m`) signed by a private key (`p`) with the corresponding public key (`q`), a malicious actor can manipulate the signature by subtracting `s` from the curve's order and flipping `v` to 27 if it's 28, or 28 if it's 27, resulting in a new signature that resolves to `q` without requiring access to `p`.
- **Parent Private Key Recovery in HD Wallets**: Addresses the scenario where, given knowledge of a parent public key and its chain code, if there is a leak of any non-hardened child wallet's private key along with the index of that child wallet, it's trivial to calculate the parent's private key. Which in turn enables derivation of all possible child private keys, specifically referring to the private key of the leaked child wallet's siblings.
