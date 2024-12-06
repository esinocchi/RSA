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

def fermat(n, k):
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
        raise ValueError("Number of bits must be positive")
    generated = False
    while not generated:
        candidate = prime_candidate(n)
        if fermat(candidate, k=15):
            generated = True
            return candidate

def generate_public(phi: int) -> int:

    common_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 65537]
    for e in common_primes:
        if e < phi and gcd(e, phi) == 1:
            return e
        
    generated = False
    while not generated:
        e = random.randint(3, phi - 1) | 1 # ensures e is odd
        if gcd(e, phi) == 1:
            generated = True
            return e
        
def extended_gcd(a: int, b: int,) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0 , 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y

def mod_inv(a: int, b: int) -> int:
    gcd, d, x = extended_gcd(a, b)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist as {a} and {b} are not coprime")
    
    return d % b
        
def generate_keypair(p: int, q: int) -> Tuple[Key, Key]:
    '''
    Description: Generates the public and private key pair
    if p and q are distinct primes. Otherwise, raise a value error
    
    Args: p, q (input integers)

    Returns: Keypair in the form of (Pub Key, Private Key)
    PubKey = (n,e) and Private Key = (n,d)
    '''
    if p == q:
        raise ValueError("p and q must be distinct primes")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = generate_public(phi)
    d = mod_inv(e, phi)

    return ((n,e), (n, d))
    

def rsa_encrypt(m: str, pub_key: Key, blocksize: int) -> int:
    '''
    Description: Encrypts the message with the given public
    key using the RSA algorithm.

    Args: m (input string)

    Returns: c (encrypted cipher)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''

    if blocksize <= 0:
        raise ValueError("Blocksize must be positive")

    n, e = pub_key
    num = chunk_to_num(m)

    if num >= n:
        raise ValueError("Message too large for given key size. Try increasing key size or reducing message length")

    c = mod_exp(num, e, n)
    return c


def rsa_decrypt(c: str, priv_key: Key, blocksize: int) -> int:
    '''
    Description: Decrypts the ciphertext using the private key
    according to RSA algorithm

    Args: c (encrypted cipher string)

    Returns: m (decrypted message, a string)
    NOTE: You CANNOT use the built-in pow function (or any similar function)
    here.
    '''
    n, d = priv_key
    c = int(c)
    m = mod_exp(c, d, n)
    word = num_to_chunk(m, blocksize)
    return word

def chunk_to_num( chunk ):
    '''
    Description: Convert chunk (substring) to a unique number mod n^k
    n is the common modulus, k is length of chunk.

    Args: chunk (a substring of some messages)

    Returns: r (some integer)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    for c in chunk:
        val = ord(c)
        if val < 32 or val > 128:
            raise ValueError("Input contains invalid characters. Only ASCII characters between 32 and 128 are supported")
        
    base = 97
    k = len(chunk)
    num = 0

    for i, ch in enumerate(chunk):
        val = ord(ch) - 32
        power = k - 1 - i
        num += val * (base**power)

    return num


def num_to_chunk( num, chunksize ):
    '''
    Description: Convert a number back to a chunk using a given 
    chunk size

    Args: num (integer), chunksize (integer)

    Returns: chunk (some substring)
    NOTE: You CANNOT use any built-in function to implement base conversion. 
    '''
    base = 97
    r = num
    word = []

    if chunksize <= 0:
        raise ValueError("Chunksize must be positive")
    if num < 0:
        raise ValueError("Number must be non-negative")

    for i in range(chunksize):
        c1 = r // (base**(chunksize-i-1))
        letter = chr(c1 + 32)
        word.append(letter)
        r = r % (base**(chunksize-i-1))
    
    return ''.join(word)