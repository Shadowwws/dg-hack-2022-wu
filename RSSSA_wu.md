# RSSSA, DG'hAck (3 solves)

## Sources

```py
import os, json
from hashlib import sha256
from Crypto.Random.random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class RSSSA:
    
    def __init__(self, N, e):
        self.s = randint(0, N-1)
        self.N, self.e = N, e
        self.P = self.gen_shamir_polynomial()
        self.key = sha256(str(self.P[-1]).encode()).digest()
        self.iv = os.urandom(16)
           
    def gen_shamir_polynomial(self):
        f = lambda x: pow(x + self.s, self.e, self.N)
        a_0 = randint (0, self.N-1)
        return [a_0, f(a_0), f(f(a_0)), f(f(f(a_0)))]

    def eval_poly(self, x):
        n = len(self.P)
        P_x = self.P[n-1]
        for i in range (n-2, -1, -1):
            P_x = (x * P_x + self.P[i]) % self.N
        return P_x
    
    def encrypt(self, data):
        E = AES.new(self.key, AES.MODE_CBC, iv = self.iv)
        return E.encrypt (pad(data, 16))

if __name__ == "__main__":
    N = 0xd73dd1b77ae0bcc27fad3d4977f998e4ea5381f21c64aa39923adf73135f0a270eb1c5c2c10d2a609e0cdee57e50ccb93c2d41d4e3bf6e898885815f574bf4dc4a0a9c4a68245d8f7a2cd2b7fab1b43f9d6f1af208f91ad3535adc087ac3f25bcd926fb85a704697e0e2e7f409693ffce4973fbf2809ae7df2e11ebe258e4fa7a7b718a6d2ef0b64ded43ca7ed2c6682b9db2c9795727bb685b1ee2fc080dd08e262129419a930520ec1a0a4196a6b06ccaa1eadb4ea368bfc97fed2d7f3b367f9d0d7cab97aa4b188126198849db10c52b59a7044515c50f6d67b9810b9244cdb6f7b4e579eac1bd682355a87826bbee880fa49f167fc453b0f8bd4451e716b
    e = 3
    chal = RSSSA(N, e)
    flag = open("flag.txt", "rb").read().strip()
    enc = chal.encrypt(flag)
    iv = chal.iv
    for _ in range (3):
        try:
            p = int (input("[RSSSA] Enter a point! "))
            print(json.dumps({
                "i": p,
                "P(i)": chal.eval_poly(p)
            }))
        except ValueError:
            print (json.dumps({
                "error": "wrong input"
            }))
    print("[RSSSA] Now guess my secret")
    print (json.dumps({
        "iv": iv.hex(),
        "enc": enc.hex(),
    }))
```

We are provided this script which is running on a server. So the program is based on RSA and Shamir Secret Sharing as expected .

It firsts create a random number `s` between 0 and `N` and uses this number as the secret of the SSS. 
Each coefficient is computed based on the previous one following this formula :

a<sub>i+1</sub> = (a<sub>i</sub> + s)<sup>e</sup> mod N

This is our RSA part.

Then it's standard Shamir Secret Sharing :

	-We give an x coordinate
	-It is evaluated with the coefficients
	-It gives us the y coordinate

We can only have 3 points.

## Solve

Our goal is to recover the secret because it's the key used to encrypt the flag with AES.

To use Lagrange Interpolation (as in standard SSS) we would need to have 4 points, unfortunately we can only have 3 of them so we have to exploit a breach somewhere.

A key requirement of SSS is that the coefficients of the polynomial are random between each others, however here they are related with the RSA cryptosystem so this is likely our entry point.

The idea is to see that all the coefficients only depend on `s` and hence we have only one unknown variable. Thinking that way, our coefficients become :

[a<sub>0</sub>,
(a<sub>0</sub> + s)<sup>e</sup> mod N, 
((a<sub>0</sub> + s)<sup>e</sup>+s)<sup>e</sup> mod N,
(((a<sub>0</sub> + s)<sup>e</sup>+s)<sup>e</sup>+s)<sup>e</sup> mod N]

Replacing that in the ``eval_poly`` function gives the following equation with input our `x` and output the corresponding `y` :

y = x \* (x \* (x * ( ( (a<sub>0</sub> + s)<sup>e</sup>+s)<sup>e</sup>+s)<sup>e</sup> + ( (a<sub>0</sub> + s)<sup>e</sup> + s)<sup>e</sup> )+(a<sub>0</sub> + s)<sup>e</sup> )+a<sub>0</sub> mod N

This equation looks complicated but the thing to notice is that we still only have one unknown variable `s` ( and a<sub>0</sub> but it's easy to recover).

Now comes the part that took me some time to find, the polynomial gcd. I'm pretty sure you know the gcd between two numbers, well, it also exists between polynomial and it works almost the same way. The result is the biggest polynomial that divides the two.

A one line implementation of it :
```py
pgcd = lambda g1, g2: g1.monic() if not g2 else pgcd(g2, g1%g2)
```
As you can see it works the same way.

Knowing that our goal is to have 2 polynomials like this one 

x \* (x \* (x * ( ( (a<sub>0</sub> + s)<sup>e</sup>+s)<sup>e</sup>+s)<sup>e</sup> + ( (a<sub>0</sub> + s)<sup>e</sup> + s)<sup>e</sup> )+(a<sub>0</sub> + s)<sup>e</sup> )+a<sub>0</sub> -y mod N

with 2 different x and then take their gcd. Because their common root is `s`, the result of the gcd will be :
`x +/- s = 0 mod N`

Let's implement this

We need a<sub>0</sub>, which can be easily recovered by sending the x-coordinate `0`.

We need 2 different polynomials so we can take x = 1 and x = 2.

Final script :
```py
from hashlib import sha256
from Crypto.Random.random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pwn import remote
import json

def f(a):
	return (x+a)^3

pgcd = lambda g1, g2: g1.monic() if not g2 else pgcd(g2, g1%g2)

n = 0xd73dd1b77ae0bcc27fad3d4977f998e4ea5381f21c64aa39923adf73135f0a270eb1c5c2c10d2a609e0cdee57e50ccb93c2d41d4e3bf6e898885815f574bf4dc4a0a9c4a68245d8f7a2cd2b7fab1b43f9d6f1af208f91ad3535adc087ac3f25bcd926fb85a704697e0e2e7f409693ffce4973fbf2809ae7df2e11ebe258e4fa7a7b718a6d2ef0b64ded43ca7ed2c6682b9db2c9795727bb685b1ee2fc080dd08e262129419a930520ec1a0a4196a6b06ccaa1eadb4ea368bfc97fed2d7f3b367f9d0d7cab97aa4b188126198849db10c52b59a7044515c50f6d67b9810b9244cdb6f7b4e579eac1bd682355a87826bbee880fa49f167fc453b0f8bd4451e716b
P.<x> = PolynomialRing(Zmod(n))

r = remote("rsssa.chall.malicecyber.com",4999)

r.recvuntil(b"point! ")

r.sendline(b"0") # get a0

a0 = int(json.loads(r.recvline().decode())["P(i)"])

r.recvuntil(b"point! ")

x0 = 1

r.sendline(str(x0).encode()) # get first polynomial

y0 = int(json.loads(r.recvline().decode())["P(i)"])

r.recvuntil(b"point! ")

x1 = 2

r.sendline(str(x1).encode()) # get second polynomial

y1 = int(json.loads(r.recvline().decode())["P(i)"])

r.recvline()

data = json.loads(r.recvline().decode())

# compute the 3 coefficients
m = f(a0)
n = f(f(a0))
o = f(f(f(a0)))

# Construction of the 2 polynomials
f = x0*(x0*(x0*o+n)+m)+a0 - y0
g = x1*(x1*(x1*o+n)+m)+a0 - y1

h = pgcd(f,g)

print(h)
# Get s from the gcd of the polys
s = n-int(h.coefficients()[0])

k = lambda y: (y + s)^ 3% n

sh = k(k(k(a0))) %n

key = sha256(str(sh).encode()).digest()

print(unpad(AES.new(key,AES.MODE_CBC, iv = bytes.fromhex(data["iv"])).decrypt(bytes.fromhex(data["enc"])),16))
```

Flag : DGA{y0u_r3_4_sm4rt_455_guy_y0u_sh0uld_r34lly_w0rk_w1th_u3}
