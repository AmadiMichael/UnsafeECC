
from ECC import (
    bytes_to_int,
    ecdsa_raw_verify,
    privtopub,
    Tuple,
)
from py_ecc.typing import PlainPoint2D



def generate_easy_fake_signature(pub: PlainPoint2D) -> (bytes, Tuple[int, int, int]):
    # Given that signatures are verified this way. Q is public key
    #   s1 = s ** -1
    #   a = G * (h * s1)
    #   b = Q * (r * s1)
    #   c = a + b
    #   c.x = r
    # 
    # We can see that the only check is ensuring that `c.x == r`
    #
    # EASY FAKE SIGNATURE
    # If we can ensure that `a == 0` and `b == Q`,
    # that would mean that c would be the same as the public key
    #
    # So how can we do that, 
    # To make `a` be 0, we can ensure that `h * s1` == 0. To do this we can set `h` to 0
    # Why not `s1`? We will find out soon
    #
    # Next, to make `b` to be the public key, we can simply make `r * s1` to be 1. 
    # To do this, we can just ensure that r is the multiplicative inverse of s1
    #
    # Lastly, since we need `c.x == r`, that means `r` must be the same as the x axis of the public key (since c will also be the public key)
    # 
    # That's it
    #
    # So in theory all we need to do is
    # h = 0
    # r = Q.x
    # s = inv(Q.x)
    #
    # And this magically creates a valid formula for any Q without knowing it's private key
    #
    # let's see the calculation and it's results
    #
    # a = G * (0 * inv(Q.x)) // this will be (0, 0)
    # b = Q * (Q.x * inv(Q.x)) // this will be Q
    # c = a + b // this will be Q
    # c.x == r // this will be true!

    message = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    easy_fake_sig = (27, pub[0], pub[0])
    
    assert ecdsa_raw_verify(message, easy_fake_sig, pub)
    
    print("successful!")
    return (bytes_to_int(message), easy_fake_sig)




a_priv = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
a_pub = privtopub(a_priv) 
print(generate_easy_fake_signature(a_pub))