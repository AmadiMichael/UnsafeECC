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
    vrs1: Tuple[int, int, int],
    leaked_nonce: int
) -> bytes:
    # K should never leak!
    #   r = multiply(G, k).x
    #   k1 = inv(k)
    #   s = k1 * (msghash + (p * r))
    #   
    # If k is known, we can easily do (same as the second formula for recovering private key from nonce reuse)
    #   s = pow(k, -1, N) * (msghash + (priv * r)) mod N
    #   s * k = msghash + priv * r
    #   s * k - msghash = priv * r
    #   ((s * k) - msghash1) * pow(r, -1, N) = priv
    
    v1, r1, s1 = vrs1
    x, y = multiply(G, leaked_nonce)
    
    # Simple check to determine if s was flipped to make it be in the lower order of N
    # If so flip it back
    s1 = s1 if y % 2 == 0 and v1 == 27 or y % 2 == 1 and v1 == 28 else N - s1
    p = (((s1 * leaked_nonce) - bytes_to_int(msghash1)) * pow(r1, -1, N)) % N
    return p.to_bytes(32)




## Test
def test_it(priv: bytes, message: bytes, leaked_nonce: int):
    # get public key of priv
    pub = privtopub(priv)
    
    # use priv to sign message1 with a nonce and ensure it recovers to pub
    sig = ecdsa_unsafe_sign(message, leaked_nonce, priv)
    assert ecdsa_raw_verify(message, sig, pub)
    
    # call the recover_private_key fn to get the recovered private key
    recovered_priv = recover_private_key(message, sig, leaked_nonce)
    assert priv == recovered_priv
    
    # success
    print("successful!")
    print(bytes_to_int(recovered_priv))
    
    
    
# run it
a_priv_key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
a_message = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
a_nonce_to_reuse = 5

test_it(a_priv_key, a_message, a_nonce_to_reuse)