# UNAUDITED: DO NOT USE IN PRODUCTION

from ECC import (
    bytes_to_int,
    privtopub,
    multiply, 
    add,
    N, 
    G,
)
from py_ecc.typing import PlainPoint2D
from random import randint
from sha3 import keccak_256

def int_to_bytes(integer) -> int:
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'big')


# MINI DOUBLE KEY STEALTH ADDRESS IMPLEMENTATION



# ACTIONS OF THE PAYER
#
# stealth_meta_address[0]: view public key,
# stealth_meta_address[1]: spend public key,
# return (stealth_public_key, ephemeral_public_key, view_tag)
def generate_stealth_address_from_stealth_meta_address(stealth_meta_address: [PlainPoint2D, PlainPoint2D]) -> (PlainPoint2D, PlainPoint2D, int, int):
    # generate ephemeral key pair
    ephemeral_priv_key = randomPrivateKey()
    ephemeral_public_key = privtopub(int_to_bytes(ephemeral_priv_key))
    
    # calculate shared secret
    shared_secret = multiply(stealth_meta_address[0], ephemeral_priv_key)
    
    # calculate the stealth meta address
    Q = keccak_256(int_to_bytes(shared_secret[0]) + int_to_bytes(shared_secret[1])).digest()
    
    view_tag = Q[0] # most significant byte
    stealth_public_key = add(multiply(G, bytes_to_int(Q)), stealth_meta_address[1])
    
    return (stealth_public_key, ephemeral_public_key, ephemeral_priv_key, view_tag)



# ACTIONS OF USERS THAT HAVE BROADCASTED THEIR STEALTH META ADDRESS AND SCANNING TO DETECT IF/WHEN THEY RECEIVE A PAYMENT
def get_stealth_address_private_key(stealth_public_key: PlainPoint2D, ephemeral_public_key: PlainPoint2D, view_tag: int) -> int:
    # calculate shared secret
    shared_secret = multiply(ephemeral_public_key, bobs_view_priv_key)
    
    # calculate the stealth meta address
    Q = keccak_256(int_to_bytes(shared_secret[0]) + int_to_bytes(shared_secret[1])).digest()
    # compare view tags
    if Q[0] != view_tag:
        return 0
    
    # confirm it's the same address
    calc_stealth_public_key = add(multiply(G, bytes_to_int(Q)), bobs_spend_public_key)
    # compare stealth public keys
    if calc_stealth_public_key != stealth_public_key:
        return 0
    
    # get the priv key
    stealth_priv_key = (bytes_to_int(Q) + bobs_spend_priv_key) % N
    
    # is always be true, sanity check
    assert stealth_public_key == multiply(G, stealth_priv_key)
    
    # priv key
    return stealth_priv_key






# PITFALL HELPERS 

def randomPrivateKey() -> int:
    return randint(0, N)


# `public_key` and `private_key` inputs here must be either 
#  - (view public key, ephemeral private key) or
#  - (ephemeral public key, view private key)
#
# It must be this way in order to correctly derive the shared secret
# Remember that at all stealth transfers, the view public key and ephemeral public key are always public so the work for an attacker is to get the ephemeral or view private key
#
# spend_public_key is of course the spend public key
# This is also already public as it's broadcasted by the receiver as part of the stealth meta address
def generate_stealth_address(public_key: PlainPoint2D, private_key: int, spend_public_key) -> PlainPoint2D:
    # calculate shared secret
    shared_secret = multiply(public_key, private_key)
    
    # calculate the offset of the stealth address
    Q = keccak_256(int_to_bytes(shared_secret[0]) + int_to_bytes(shared_secret[1])).digest()
    
    # calculate stealth address
    stealth_public_key = add(multiply(G, bytes_to_int(Q)), spend_public_key)
    
    return stealth_public_key



# `public_key` and `private_key` inputs here must be either 
#  - (view public key, ephemeral private key) or
#  - (ephemeral public key, view private key)
#
# It must be this way in order to correctly derive the shared secret
# Remember that at all stealth transfers, the view public key and ephemeral public key are always public so the work for an attacker is to get the ephemeral or view private key
#
# spend_private_key is of course the spend private key
def generate_stealth_address_private_key(public_key: PlainPoint2D, private_key, spend_private_key: int) -> int:
    # calculate shared secret
    shared_secret = multiply(public_key, private_key)
    
    # calculate the offset of the stealth address private key
    Q = keccak_256(int_to_bytes(shared_secret[0]) + int_to_bytes(shared_secret[1])).digest()
    
    # calculate the private key
    stealth_address_private_key = bytes_to_int(Q) + spend_private_key
    
    return stealth_address_private_key













# BOB INIT
bobs_view_priv_key = randomPrivateKey()
bobs_spend_priv_key = randomPrivateKey()
bobs_view_public_key = privtopub(int_to_bytes(bobs_view_priv_key))
bobs_spend_public_key = privtopub(int_to_bytes(bobs_spend_priv_key))
bobs_stealth_meta_address = [bobs_view_public_key, bobs_spend_public_key]



# TX-1: Alice sends tokens to Bob's stealth address generated from his stealth meta address
(bobs_1_stealth_public_key, alices_ephemeral_public_key, alices_ephemeral_priv_key, tx_1_view_tag) = generate_stealth_address_from_stealth_meta_address(bobs_stealth_meta_address)
print("bobs_1_stealth_public_key:", bobs_1_stealth_public_key, "\nalices_ephemeral_public_key:", alices_ephemeral_public_key, "\ntx_1_view_tag:", tx_1_view_tag, "\n")
print("Stealth address private key:", get_stealth_address_private_key(bobs_1_stealth_public_key, alices_ephemeral_public_key, tx_1_view_tag))


# TX-1: Adam sends tokens to Bob's stealth address generated from his stealth meta address
(bobs_2_stealth_public_key, adams_ephemeral_public_key, adams_ephemeral_priv_key, tx_2_view_tag) = generate_stealth_address_from_stealth_meta_address(bobs_stealth_meta_address)
print("bobs_2_stealth_public_key:", bobs_2_stealth_public_key, "\nadams_ephemeral_public_key:", adams_ephemeral_public_key, "\ntxs_view_tag:", tx_2_view_tag, "\n")
print("Stealth address private key:", get_stealth_address_private_key(bobs_2_stealth_public_key, adams_ephemeral_public_key, tx_2_view_tag))







# Attack scenarios from Charlie
#
#
# - If charlie gets access to ephemeral private key of 1 tx, privacy is leaked! but only for that particular stealth address generated by alice's ephemeral keypair
assert(generate_stealth_address(bobs_view_public_key, alices_ephemeral_priv_key, bobs_spend_public_key) == bobs_1_stealth_public_key)
assert(generate_stealth_address(bobs_view_public_key, alices_ephemeral_priv_key, bobs_spend_public_key) != bobs_2_stealth_public_key)
#
#
# - If charlie gets access to Bob's view private key, privacy is leaked! For all past and future stealth addresses generated from bobs stealth meta address
assert(generate_stealth_address(alices_ephemeral_public_key, bobs_view_priv_key, bobs_spend_public_key) == bobs_1_stealth_public_key)
assert(generate_stealth_address(adams_ephemeral_public_key, bobs_view_priv_key, bobs_spend_public_key) == bobs_2_stealth_public_key)
#
#
# - If both leaks, the ephemeral private key is not useful as the view private key can breach privacy for that particular tx and every other txs
assert(generate_stealth_address(alices_ephemeral_public_key, bobs_view_priv_key, bobs_spend_public_key) == bobs_1_stealth_public_key)
assert(generate_stealth_address(adams_ephemeral_public_key, bobs_view_priv_key, bobs_spend_public_key) == bobs_2_stealth_public_key)
#
#
# - If only the spend private key leaks, nothing is breached (both security and privacy) because we do not have access to the shared secret to generate the stealth address or it's private key
#
#
# - If the spend private key leaks with the ephemeral private key of 1 tx, both privacy (as we saw above) and security is breached. but only for that particular stealth address generated by alice's ephemeral keypair
assert(multiply(G, generate_stealth_address_private_key(bobs_view_public_key, alices_ephemeral_priv_key, bobs_spend_priv_key)) == bobs_1_stealth_public_key)
assert(multiply(G, generate_stealth_address_private_key(bobs_view_public_key, alices_ephemeral_priv_key, bobs_spend_priv_key)) != bobs_2_stealth_public_key)
#
#
# - If the spend private key leaks with the view private key, both privacy (as we saw above) and security is breached! For all past and future stealth addresses generated from bobs stealth meta address
assert(multiply(G, generate_stealth_address_private_key(alices_ephemeral_public_key, bobs_view_priv_key, bobs_spend_priv_key)) == bobs_1_stealth_public_key)
assert(multiply(G, generate_stealth_address_private_key(adams_ephemeral_public_key, bobs_view_priv_key, bobs_spend_priv_key)) == bobs_2_stealth_public_key)
#
#
# - If the spend private key leaks with both the view and ephemeral private keys, the ephemeral private key is not useful as the view private key can breach privacy for both that particular tx and every other txs
assert(multiply(G, generate_stealth_address_private_key(alices_ephemeral_public_key, bobs_view_priv_key, bobs_spend_priv_key)) == bobs_1_stealth_public_key)
assert(multiply(G, generate_stealth_address_private_key(adams_ephemeral_public_key, bobs_view_priv_key, bobs_spend_priv_key)) == bobs_2_stealth_public_key)