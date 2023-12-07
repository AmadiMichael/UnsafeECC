# Unsafe ECC

Proof of concept and explainers to ECC vulnerabilities. It doesn't just tell you "Don't do this, it is exploitable. Do this rather', it also shows you how exactly it's exploitable and how the formula is derived.

## Includes

- Nonce reuse: Covers how, given two signatures `s1` and `s2` of messages `m1` and `m2` respectively, signed by a private key `p` whose public key is `q`, a malicious actor can calculate and get `p` using just `s1`, `s2`, `m1` and `m2`
- Fake signatures : Covers how, given a private key `p` and a public key `q`, a malicious actor can generate a signature and message pair that recovers to `q` without the exploiter knowing or having access to `p`
- Signature malleability: Covers how given a signature (`v`, `r` and `s`) of message `m` signed by private key `p` whose public key is `q`, a malicious actor can subtract `s` from the order of the curve and flip `v` to 27 if it's 28 or 28 if it's 27 to get a new signature that recovers to `q` (no need to have access to `p`)
