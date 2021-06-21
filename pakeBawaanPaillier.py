import random
from nose.tools import assert_raises
import paillier

import sys

a = 5
b = 10

priv, pub = paillier.generate_keypair(128)
print(priv)
print(pub)

ca, cb = paillier.encrypt(pub, a), paillier.encrypt(pub, b)

print("A: ", a)
print("B: ", b)
print("Cipher(A): ", ca)
print("Cipher(B): ", cb)

cs = paillier.e_add(pub, ca, cb)
print("cs : ", cs)

cs = paillier.e_add_const(pub, ca, b)
s = paillier.decrypt(priv, pub, cs)
print("Hasil (Add): ", s)

cs = paillier.e_mul_const(pub, ca, b)
s = paillier.decrypt(priv, pub, cs)
print("Hasil (Mult): ", s)

'''p = 101
iinv = paillier.invmod(a, p)
print("(Valx", a, ") mod 101 = 1. Val: ", iinv)'''
