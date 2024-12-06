# -----------------------------------------------------------------------
# SP24 CMPSC 360 Extra Credit Assignment 2
# RSA Implementation
# 
# Name: Evan Sinocchi
# ID: ezs5772
# 
# 
# You cannot use any external/built-in libraries to help compute gcd
# or modular inverse. You cannot use RSA, cryptography, or similar libs
# for this assignment. You must write your own implementation for generating
# large primes. You must wirte your own implementation for modular exponentiation and
# modular inverse.
# 
# You are allowed to use randint from the built-in random library
# -----------------------------------------------------------------------

from typing import Tuple
import random
import math

# Type defs
Key = Tuple[int, int]

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_exp(base, exp, mod):
    result = 1
    current = base % mod
    e = exp
    while e > 0:
        if e % 2 == 1:
            result = (result * current) % mod
        current = current**2 % mod
        e //= 2
    return result

def fermat(n, k=10):
    if n < 2:
        return False
    if n in (2,3):
        return True
    for i in range(k):
        a = random.randint(2, n-2)
        if mod_exp(a, n-1, n) != 1:
            return False
    return True

def generate_nbit_num(n):
    if n <= 1:
        return 2
    low = 1 << (n-1)
    high = (1 << n) - 1
    return random.randint(low, high)

def prime_candidate(n):
    candidate = generate_nbit_num(n)
    if candidate % 2 == 0:
        candidate += 1
    return candidate


def generate_prime(n: int) -> int:
    '''
    Description: Generate an n-bit prime number
    Args: n (No. of bits)
    Returns: prime number
    
    NOTE: This needs to be sufficiently fast or you may not get
    any credit even if you correctly return a prime number.
    '''

    if n < 1:
        raise ValueError
    generated = False
    while not generated:
        candidate = prime_candidate(n)
        if fermat(candidate, k=15):
            generated = True
            return candidate
        else:
            candidate = prime_candidate(n)

def generate_keypair(p: int, q: int) -> Tuple[Key, Key]:
    '''
    Description: Generates the public and private key pair
    if p and q are distinct primes. Otherwise, raise a value error
    
    Args: p, q (input integers)

    Returns: Keypair in the form of (Pub Key, Private Key)
    PubKey = (n,e) and Private Key = (n,d)
    '''
    raise NotImplementedError


def rsa_encrypt(m: str, pub_key: Key, blocksize: int) -> int:
    '''
    Description: Encrypts the message with the given public
    key using the RSA algorithm.

    Args: m (input string)

    Returns: c (encrypted cipher)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    raise NotImplementedError


def rsa_decrypt(c: str, priv_key: Key, blocksize: int) -> int:
    '''
    Description: Decrypts the ciphertext using the private key
    according to RSA algorithm

    Args: c (encrypted cipher string)

    Returns: m (decrypted message, a string)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    raise NotImplementedError


def chunk_to_num( chunk ):
    '''
    Description: Convert chunk (substring) to a unique number mod n^k
    n is the common modulus, k is length of chunk.

    Args: chunk (a substring of some messages)

    Returns: r (some integer)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    raise NotImplementedError


def num_to_chunk( num, chunksize ):
    '''
    Description: Convert a number back to a chunk using a given 
    chunk size

    Args: num (integer), chunksize (integer)

    Returns: chunk (some substring)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    raise NotImplementedError

print(generate_prime(2))