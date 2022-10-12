from lib2to3.pgen2.pgen import generate_grammar
from Crypto.Random import *
from Crypto.Util import *
from Crypto.Util.Padding import *
from Crypto.Util.number import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import random

def main():

    message0 = b'Hi Bob!'
    message1 = b'Hi Alice!'
    iv = get_random_bytes(16)

    e = 65537
    p = 125964645423958069741744529872772275038609514555435541608216390604613823459381408660806745193581739918797012549128245959891659812698434245387059165798100501363151789084691139085011954092422539136437549572179511222633223746890903774122843224374028408054546752077447681061255351436619998981366579355763403617113
    q = 152095254918764933056617056633930033605024647767903251578815696981217507850462368353063951686915545480449471554404723941192966893631764783804562619505069589457786904313605972166124992689628638482920436448339710705231485899897658846004179205102097454882808616247021503534956636236244846643236042129095806861711
    n = p * q
    et = (p-1) * (q-1)
    d = pow(e, -1, et)
    # Alice sends e and n to Bob
    # Public Key (e, n)
    # Private Key (t, n)

    
    # Bob computes secret, sends secret to Alice
    x = random.randint(0, n)
    c = pow(x, e, n)

    # Alice decrypts secret, both generate keys for AES
    secret = pow(c, d, n)
    print("\nIs Alice's secret identical to Bob's?")
    print("Comparison: " + str(x == secret))

    # SHA256 with their secret, leads to same hash
    kA = SHA256.new()
    kA.update(secret.to_bytes(256, 'big'))
    kB = SHA256.new()
    kB.update(x.to_bytes(256, 'big'))

    # encrypt with the SHA hash, CBC, with the same iv
    cbcAlice = AES.new(kA.digest()[:16], AES.MODE_CBC, iv)
    cbcBob = AES.new(kB.digest()[:16], AES.MODE_CBC, iv)

    # encrypt the messages and send them out
    c0 = cbcAlice.encrypt(pad(message0, 16))
    c1 = cbcBob.encrypt(pad(message1, 16))

    # decrypt eachother's messages to find what they said!
    decA = unpad(AES.new(kA.digest()[:16], AES.MODE_CBC, iv).decrypt(c1), 16)
    decB = unpad(AES.new(kB.digest()[:16], AES.MODE_CBC, iv).decrypt(c0), 16)

    print("\nMessages after decryption:")
    print(decA, decB)

    # Mallory knows Alice's public key, and can use it
    # and the information after Alice decrypts her
    # modified message to learn the secret s
    addOn = (pow(2, e) * c)
    combo = pow(addOn, d, n) // 2
    print(combo)
    print()
    print(secret)

    test1 = pow(int('Hi Alice!'.encode().hex(), 16), d, n)
    test2 = pow(int('Hi Bob!'.encode().hex(), 16), d, n)
    test3 = (test1 * test2) % n

    print()
    print(test1)
    print()
    print(test2)
    print()
    print(test3)







if __name__ == "__main__":
    main()