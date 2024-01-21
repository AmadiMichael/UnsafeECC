import hashlib
import hmac
from py_ecc.typing import PlainPoint2D
from hexbytes import (
    HexBytes,
)
from ECC import (
    bytes_to_int,
    privtopub,
    add,
    N, 
    G,
)



# HELPER FUNCTIONS, EXPLOIT FUNCTION CAN BE FOUND BELOW

def int_to_bytes(integer) -> int:
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'big')

def compress_pub_key(pub_key: PlainPoint2D) -> bytes:
        pub_key_parity_prefix = (2).to_bytes(1, 'big') if pub_key[1] % 2 == 0 else (3).to_bytes(1, 'big')
        return pub_key_parity_prefix + pub_key[0].to_bytes(32, 'big')



def derive(hd_parent_node_info: (PlainPoint2D, int, int), index: int, isHardened: bool) -> (PlainPoint2D, int, int):
    parent_public_key = hd_parent_node_info[0]
    parent_priv_key = hd_parent_node_info[1]
    parent_chain_code = hd_parent_node_info[2]
    
    if isHardened:
        index = 2147483648 + index
        hash = hmac.new(parent_chain_code.to_bytes(32, 'big'), (0).to_bytes(1, 'big') + parent_priv_key.to_bytes(32, 'big') + index.to_bytes(4, 'big'), digestmod=hashlib.sha512).digest()
    else:
        hash = hmac.new(parent_chain_code.to_bytes(32, 'big'), compress_pub_key(parent_public_key) + index.to_bytes(4, 'big'), digestmod=hashlib.sha512).digest()
    
    offset = hash[0:32]
    child_chaincode = bytes_to_int(hash[32:64])
    pub_offset = privtopub(offset)

    child_private_key = bytes_to_int(offset) + parent_priv_key
    child_pub_key = add(parent_public_key, pub_offset)
    
    return (child_pub_key, child_private_key, child_chaincode)



# This works for non hardened nodes because the hash is determined from the parent chaincode, parent public key and child index, if we have all three and the child private key we can easily get the parent private key
# Does not work hardened nodes because the hash if determined from the parent chaincode, parent private key and child index, and trying to get the parent private key by using the parent private key defeats the purpose
# 
# THE OBVIOUS QUESTION IS WHY NOT HARDEN EVERYTHING
# One benefit of HD wallets is being able to generate child addresses by only having the parent public key and chain code. This is helpful for audits and generating one time addresses on an untrusted server
#
# How paths are defined (an apostrophe means it's a hardened path):
#   "m / purpose' / coin_type' / account' / change / address_index"
# All child wallets from the account derivation path and before are hardened, the change path and address_index path is not to facilitate the above use case


# INDEPTH
#
# The exploit works as follows
# Since
#   child_private_key = offset + parent_private_key
# that means that
#   parent_private_key = child_private_key - offset
# 
# This means that if we can get the `offset` value and any `child_private_key` derived from this parent node, we can get the `parent_private_key` and hence all possible child private keys, 
# specifically referring to the private key of the leaked child wallet's siblings.
#
#
# First let's see how we can get `offset`
# Recall that for non-hardened child wallets
#   offset = sha512({k: chainCode, v: compressedPublicKey.append(index as bytes4))
# 
# Notice how these parameters are not explicitly secret values or advertised to always be private
# This means that if we can get the parent's `chainCode`, the parent's public key and the index of the `child_private_key` we have the we can easily get the `offset`
#
# For the `child_private_key`, that's not going to be as easy to get as any of the above but let's assume we have 1 for the POC below


# values from base derivation path "m" using Bitcoin seed and mnemonic "critic august page curtain lion scene poverty over empty system lady useless"
global_hd_master_priv = 7689162646347254789289457585570777995548838195840484586546417750201678994478
global_hd_master_pub = privtopub(int_to_bytes(global_hd_master_priv))
global_chaincode = 104326670430597193981057684893345542428774993972637944294968933122272829988816
global_hd_master_node_info = (global_hd_master_pub, global_hd_master_priv, global_chaincode)

# derivation paths steps, ethereum uses "m/44'/60'/0'/0/0"
# m/44'
m_44prime = derive(global_hd_master_node_info, 44, True)
# m/44'/60'
m_44prime_60prime = derive(m_44prime, 60, True)
# m/44'/60'/0'
m_44prime_60prime_0prime = derive(m_44prime_60prime, 0, True)
# m/44'/60'/0'/0
m_44prime_60prime_0prime_0 = derive(m_44prime_60prime_0prime, 0, False)
# m/44'/60'/0'/0/0
m_44prime_60prime_0prime_0_0 = derive(m_44prime_60prime_0prime_0, 0, False)



# Exploit function
def get_parent_private_key(parent_pub_key: PlainPoint2D, child_private_key: int, index_of_child: int, parent_chain_code: int) -> int:
    hash = hmac.new(parent_chain_code.to_bytes(32, 'big'), compress_pub_key(parent_pub_key) + index_of_child.to_bytes(4, 'big'), digestmod=hashlib.sha512).digest()
    
    offset = bytes_to_int(hash[0:32])
    parent_priv_key = (child_private_key - offset) % N
    
    return parent_priv_key


# Exploit
recoveredParentPublicKey = get_parent_private_key(m_44prime_60prime_0prime_0[0], m_44prime_60prime_0prime_0_0[1], 0, m_44prime_60prime_0prime_0[2])
assert(recoveredParentPublicKey == m_44prime_60prime_0prime_0[1])