from ECC import (
    multiply, 
    add, 
    bytes_to_int, 
    ecdsa_raw_recover, 
    ecdsa_unsafe_sign, 
    ecdsa_raw_verify,
    privtopub,
    Tuple,
    N, G
)


# Function that recovers the public key from two signatures signed with the same `random` nonce
def recover_private_key(
    msghash1: bytes,
    msghash2: bytes,
    vrs1: Tuple[int, int, int],
    vrs2: Tuple[int, int, int],
) -> int:
    # How signing of a message works (s1 is how s for msghash1 is derived, s2 is how s for msghash2 is derived)
    #   r = multiply(G, k).x
    #   s1 = pow(k, -1, N) * (msghash1 + (priv * r)) mod N
    #   s2 = pow(k, -1, N) * (msghash2 + (priv * r)) mod N
    #
    # We want to get k from the formula of s by making it the subject of the formula, since we have 2 s values from the same nonce, that means we have all parts of the formula apart from priv and k
    # Since priv is the same for both sides and nonce is the same for both sides, we can cancel them out. Let's see this for ourselves
    # Subtract both equations.
    #   (s1 - s2) mod N = (pow(k, -1, N) * (msghash1 + (priv * r)) mod N) - (pow(k, -1, N) * (msghash2 + (priv * r)) mod N) mod N
    #   (s1 - s2) mod N = pow(k, -1, N) * ((msghash1 + (priv * r) mod N) - (msghash2 + (priv * r) mod N)) mod N
    #   k * (s1 - s2) mod N = msghash1 + (priv * r) - msghash2 - (priv * r) mod N
    #   k * (s1 - s2) mod N = msghash1 - msghash2 mod N
    #   k = pow((s1 - s2), -1, N) * msghash1 - msghash2 mod N
    #
    # now we have k we can easily get the private key from any sig verification parameter set by making it the subject of the formula since we have every other parameter apart from the priv key itself
    #   s1 = pow(k, -1, N) * (msghash1 + (priv * r)) mod N
    #   s1 * k = msghash1 + priv * r
    #   s1 * k - msghash1 = priv * r
    #   ((s1 * k) - msghash1) * pow(r, -1, N) = priv
    #
    #
    # hence relevant formulars are
    #   k = pow((s1 - s2), -1, N) * msghash1 - msghash2 mod N
    #   priv = ((s1 * k) - msghash1) * pow(r, -1, N)

    if ecdsa_raw_recover(msghash1, vrs1) != ecdsa_raw_recover(msghash2, vrs2):
        raise Exception("Two signatures do not recover to the same address")

    v1, r1, s1 = vrs1
    v2, r2, s2 = vrs2

    # if s1 and s2 are different orders of the curve we get a wrong result.
    # turn s2 to be in the same order of the curve as s1
    # v2 should be flipped too but in our case we do not use it so we ignore it
    s2 = s2 if v1 == v2 else N - s2
    k = (pow((s1 - s2), -1, N) * (bytes_to_int(msghash1) - bytes_to_int(msghash2))) % N
    p = (((s1 * k) - bytes_to_int(msghash1)) * pow(r1, -1, N)) % N

    return p.to_bytes(32)




## Test
def test_it(priv: bytes, message1: bytes, message2: bytes, reused_nonce: int):
    # get public key of priv
    pub = privtopub(priv)
    
    # use priv to sign message1 with a nonce and ensure it recovers to pub
    sig1 = ecdsa_unsafe_sign(message1, reused_nonce, priv)
    assert ecdsa_raw_verify(message1, sig1, pub)
    
    # do the same for sig2 and use the same nonce to sign it
    sig2 = ecdsa_unsafe_sign(message2, reused_nonce, priv)
    assert ecdsa_raw_verify(message2, sig2, pub)
    
    
    # call the recover_private_key fn to get the recovered private key
    recovered_priv = recover_private_key(message1, message2, sig1, sig2)
    assert priv == recovered_priv
    
    # success
    print("successful!")
    print(bytes_to_int(recovered_priv))
    
    
    
# run it
a_priv_key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
a_message = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
a_diff_message = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000004")
a_nonce_to_reuse = 5

test_it(a_priv_key, a_message, a_diff_message, a_nonce_to_reuse)