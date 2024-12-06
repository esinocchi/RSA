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

# Type definitions for RSA keys
Key = Tuple[int, int]


# Helper functions
def gcd(a: int, b: int) -> int:
   while b != 0:
       a, b = b, a % b
   return a

def extended_euclid(a: int, b: int) -> Tuple[int,int,int]:
   if b == 0:
       return (a, 1, 0)
   g, x1, y1 = extended_euclid(b, a % b)
   x = y1
   y = x1 - (a // b)*y1
   return (g, x, y)

def mod_inv(a: int, m: int) -> int:
   g, x, z = extended_euclid(a, m)
   if g != 1:
       raise ValueError("Modular inverse does not exist.")
   return x % m

def mod_exp(base: int, exp: int, modulus: int) -> int:
   result = 1
   current = base % modulus
   e = exp
   while e > 0:
       if e & 1:  # If exponent bit is 1
           result = (result * current) % modulus
       current = (current * current) % modulus  # Square step
       e >>= 1  # Right shift exponent
   return result

# Prime number generation and testing
def is_probable_prime(n: int, k: int=10) -> bool:
   if n < 2:
       return False
   if n in (2, 3):
       return True
   small_primes = [2,3,5,7,11,13,17,19,23,29]
   # Quick check against small primes
   for sp in small_primes:
       if n == sp:
           return True
       if n % sp == 0:
           return False
   # Fermat primality test
   for i in range(k):
       a = random.randint(2, n-2)
       if mod_exp(a, n-1, n) != 1:
           return False
   return True

def generate_random_nbit_number(n: int) -> int:
   if n <= 1:
       return 2
   lower_bound = 1 << (n-1)  # 2^(n-1)
   upper_bound = (1 << n) - 1  # 2^n - 1
   return random.randint(lower_bound, upper_bound)

def generate_prime_candidate(n: int) -> int:
   candidate = generate_random_nbit_number(n)
   if candidate % 2 == 0:
       candidate += 1
   return candidate

def generate_prime_number(n: int) -> int:
   while True:
       candidate = generate_prime_candidate(n)
       if is_probable_prime(candidate, k=15):
           return candidate

# Main Functions
def generate_prime(n: int) -> int:
   '''
   Description: Generate an n-bit prime number
   Args: n (No. of bits)
   Returns: prime number
   
   NOTE: This needs to be sufficiently fast or you may not get
   any credit even if you correctly return a prime number.
   '''
   if n < 1:
       raise ValueError("Bit size must be >= 1")
   return generate_prime_number(n)

def generate_keypair(p: int, q: int) -> Tuple[Key, Key]:
   '''
   Description: Generates the public and private key pair
   if p and q are distinct primes. Otherwise, raise a value error
   
   Args: p, q (input integers)

   Returns: Keypair in the form of (Pub Key, Private Key)
   PubKey = (n,e) and Private Key = (n,d)
   '''
   # Verify inputs are valid primes
   if p == q:
       raise ValueError("p and q must be distinct primes.")
   if (not is_probable_prime(p)) or (not is_probable_prime(q)):
       raise ValueError("p and q must be prime.") 
   
   n = p*q
   phi = (p-1)*(q-1)
   
   # Find valid public exponent e
   e = 3
   while gcd(e, phi) != 1:
       e += 1
       if e >= phi:
           raise ValueError("No suitable e found.")
   
   d = mod_inv(e, phi)
   return ((n,e),(n,d)) 

def rsa_encrypt(m: str, pub_key: Key, blocksize: int) -> str:
   '''
   Description: Encrypts the message with the given public
   key using the RSA algorithm.

   Args: m (input string)

   Returns: c (encrypted cipher)
   NOTE: You CANNOT use the built-in pow function (or any similar function)
   here.
   '''
   n, e = pub_key
   if blocksize <= 0:
       raise ValueError("Invalid blocksize")
   
   # Pad message with spaces to fit blocksize
   while len(m)%blocksize!=0:
       m+=chr(32)
       
   # Process message in blocks
   ciphertext = ""
   for i in range(0,len(m),blocksize):
       chunk = m[i:i+blocksize]
       M = chunk_to_num(chunk)
       C = mod_exp(M,e,n)
       cchunk = num_to_chunk(C, blocksize)
       cchunk = cchunk[:blocksize]
       ciphertext+=cchunk
   return ciphertext

def rsa_decrypt(c: str, priv_key: Key, blocksize: int) -> str:
   '''
   Description: Decrypts the ciphertext using the private key
   according to RSA algorithm

   Args: c (encrypted cipher string)

   Returns: m (decrypted message, a string)
   NOTE: You CANNOT use the built-in pow function (or any similar function)
   here.
   '''
   n, d = priv_key
   if blocksize<=0:
       raise ValueError("Invalid blocksize")
   if len(c)%blocksize!=0:
       raise ValueError("Invalid ciphertext length")
       
   # Process ciphertext in blocks
   plaintext = ""
   for i in range(0,len(c),blocksize):
       cchunk = c[i:i+blocksize]
       C = chunk_to_num(cchunk)
       M = mod_exp(C,d,n)
       mchunk = num_to_chunk(M, blocksize)
       mchunk = mchunk[:blocksize]
       plaintext+=mchunk
   return plaintext


def chunk_to_num(chunk: str) -> int:
   '''
   Description: Convert chunk (substring) to a unique number mod n^k
   n is the common modulus, k is length of chunk.

   Args: chunk (a substring of some messages)

   Returns: r (some integer)
   NOTE: You CANNOT use any built-in function to implement base conversion. 
   '''
   base = 96  # Range of printable ASCII characters
   num = 0
   # Convert each character to a number and combine using positional notation
   for i, ch in enumerate(chunk):
       val = ord(ch)-32  # Normalize ASCII values to start at 0
       num += val*(base**i)
   return num

def num_to_chunk(num: int, chunksize: int) -> str:
   '''
   Description: Convert a number back to a chunk using a given 
   chunk size

   Args: num (integer), chunksize (integer)

   Returns: chunk (some substring)
   NOTE: You CANNOT use any built-in function to implement base conversion. 
   '''
   base = 96
   digits = []
   # Extract digits using repeated division
   while num > 0:
       digit = num % base
       num //= base
       digits.append(chr(digit+32))  # Convert back to ASCII
   # Pad with spaces if needed
   if len(digits) < chunksize:
       digits += [chr(32)]*(chunksize - len(digits))
   return ''.join(digits)