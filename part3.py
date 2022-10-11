from Crypto.Random import *
from Crypto.Util import *
from Crypto.Util.Padding import *
from Crypto.Util.number import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import random

def main():
    # e = 65537
    e = 7
    p = 17
    q = 11
    n = p * q
    et = (p-1) * (q-1)
    d = pow(e, -1, et)
    print(d)
    # Alice sends e and n to Bob
    # Public Key (e, n)
    # Private Key (t, n)

    
    # Bob computes secret, sends secret to Alice
    x = random.randint(0, n)
    c = pow(x, e, n)

    # Alice decrypts secret, both generate keys for AES
    secret = pow(c, d, n)
    print(x, secret)

    kA = SHA256.new()
    kA.update(bytes(secret))
    kB = SHA256.new()
    kB.update(bytes(x))
    print(str(kA.hexdigest()) == str(kB.hexdigest()))




if __name__ == "__main__":
    main()