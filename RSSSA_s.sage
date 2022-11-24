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

r.sendline(b"0")

a0 = int(json.loads(r.recvline().decode())["P(i)"])

r.recvuntil(b"point! ")

x0 = 1

r.sendline(str(x0).encode())

y0 = int(json.loads(r.recvline().decode())["P(i)"])

r.recvuntil(b"point! ")

x1 = 2

r.sendline(str(x1).encode())

y1 = int(json.loads(r.recvline().decode())["P(i)"])

r.recvline()

data = json.loads(r.recvline().decode())

m = f(a0)
n = f(f(a0))
o = f(f(f(a0)))

f = x0*(x0*(x0*o+n)+m)+a0 - y0
g = x1*(x1*(x1*o+n)+m)+a0 - y1

h = pgcd(f,g)

print(h)
s = n-int(h.coefficients()[0])

k = lambda y: (y + s)^ 3% n

sh = k(k(k(a0))) %n

key = sha256(str(sh).encode()).digest()

print(unpad(AES.new(key,AES.MODE_CBC, iv = bytes.fromhex(data["iv"])).decrypt(bytes.fromhex(data["enc"])),16))