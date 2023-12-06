from ECC import (
    multiply, 
    add, 
    bytes_to_int, 
    ecdsa_raw_sign, 
    ecdsa_raw_verify,
    privtopub,
    Tuple,
    N, G
)
from py_ecc.typing import PlainPoint2D


def generate_new_signature(sig: Tuple[int, int, int]) -> Tuple[int, int, int]:
    # There a lot of resources on this but in a nutshell
    # A signature `(r, s)` is congruent to `(r, N - s)` where N is the order of the curve
    #
    #
    # A way to understand it (not directly the same) using integers and not points and the ecc formula is
    #
    # Verify formula:
    #   s1 = s ** -1
    #   a = G * (h * s1)
    #   b = Q * (r * s1)
    #   c = a + b
    #   c.x = r   
    #
    # Notice that `s` is part of both `a` and `b` that make up the final value we use to compare with `r` 
    # Picture `N - s` as negating s, 
    #
    # Because `s` is applied once on both `a` and `b`, if we change it's sign it won't affect the sign or value of `c` 
    # Let's check this:
    # - If in sig1 `a` was negative and `b` was negative that means `c` will be positive, in sig2 `a` will be positive and `b` will be positive and `c` will be positive
    # - If in sig1 `a` was positive and `b` was negative that means `c` will be negative, in sig2 `a` will be negative and `b` will be positive and `c` will be negative
    # - If in sig1 `a` was negative and `b` was positive that means `c` will be positive, in sig2 `a` will be positive and `b` will be negative and `c` will be negative
    # - If in sig1 `a` was positive and `b` was positive that means `c` will be positive, in sig2 `a` will be negative and `b` will be negative and `c` will be positive
    #
    # We can see that in all possibilities, flipping `s` does not affect the sign of `c`
    #
    #
    # Note: This is a personal analogy i use in understanding the reason this happens not a mathematical proof
    
    
    v, r, s = sig
    assert v == 27 or v == 28
    
    s = N - s
    v = 27 if v == 28 else 28
    
    return (v, r, s)




a_priv_key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
a_pub_key = privtopub(a_priv_key)
a_message = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")

a_sig = ecdsa_raw_sign(a_message, a_priv_key)
assert ecdsa_raw_verify(a_message, a_sig, a_pub_key)

a_new_sig = generate_new_signature(a_sig)
assert ecdsa_raw_verify(a_message, a_new_sig, a_pub_key)

print("Old signature:", a_sig)
print("New signature:", a_new_sig)