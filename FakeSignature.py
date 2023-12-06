from ECC import (
    multiply, 
    add, 
    inv,
    ecdsa_raw_verify,
    privtopub,
    Tuple,
    G,
    N
)
from py_ecc.typing import PlainPoint2D


def generate_fake_signature(pub: PlainPoint2D) -> (bytes, Tuple[int, int, int]):
    # HOW tf is this even possible
    # Well let's look at how signatures are verified to come from the private key `p` of a particular public key `Q`
    #   s1 = s ** -1
    #   a = G * (h * s1)
    #   b = Q * (r * s1)
    #   c = a + b
    #   c.x = r
    #
    # Now what this is actually doing is using the signing formula to derive what G * k `Gk` is since we cannot know k
    # Since r is Gk.x we can compare that. Let's derive this ourselves
    #   k1 = k ** -1
    #   s = k1 * (h + (r * p))
    #
    # we want to get Gk, let's make k the subject of the formula
    #   k = s1 * (h + (r * p))
    # 
    # And No, this cannot help us get k too since we don't know the private key
    # Note that    
    #   s1 * (h + (r * p)) === (s1 * h) + (s1 * r * p)
    #
    # You might see where this is going already
    # Next, multiply both sides by G
    #   Gk = (s1 * h * G) + (G * s1 * r * p * G)
    #
    # We don't know priv, but we know the public key so let's use that instead so that everything on the left hand side are known values
    #   Gk = (G * s1 * h) + (s1 * r * pub)
    # Same as our ec verify function if we rearrange it as
    #   Gk = G * (h * s1) + pub * (r * s1)
    #
    # okay nice, but how do we generate fake sigs
    # Well, since r is already Gx.x we already have that, 
    # What we want however to get is `s` and `h`
    # Let's call (h * s1), a and (r * s1), b
    # This means that 
    #   R = (G * a) + (pub * b)
    #
    # Note that R is Gk 
    # And we have r which is R.x
    # 
    # To get s, we can do this...
    # Remember that
    #   R = (G * a) + (pub * b)
    # And
    # Given s1 = inv(s)
    #   b = r * s1
    # So,
    #   b1 = inv(b)
    #   s = r * b1
    # 
    # As for v, since we have Gk, we can calculate it ourselves with
    #   v = 27 + (Gk.y % 2) ^ 0 if (s * 2 > N) else 1
    #
    # The message, `h` can also be calculated in a similar way
    # Given s1 = inv(s)
    #   a = h * s1
    #   a1 = inv(a)
    #   h = a * s
    #
    #
    # Now but we do not need an existing signature to do this, we can choose any random a or b and calculate from there as long as we know the address's public key
    # IN SUMMARY
    # Get:
    #   a = random value mod N
    #   b = random value mod N
    #
    # Then we calculate (all operations mod N):
    #   R = nonce * G
    #   sig.v = 27 + (R.y % 2)
    #   sig.r = R.x
    #   sig.s = R.x * inv(b)
    #   h = a * s
    #
    
    
    a = 42
    b = 24

    R = add(multiply(G, a), multiply(pub, b))
    sig = (27 + R[1] % 2, R[0] % N, (R[0] * inv(b, N)) % N)

    message = (a * sig[2]) % N
    
    assert ecdsa_raw_verify(message.to_bytes(32), sig, pub)

    return (message, sig)
    
    
    




# Test
a_priv = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
a_pub_key = privtopub(a_priv)

print(generate_fake_signature(a_pub_key))