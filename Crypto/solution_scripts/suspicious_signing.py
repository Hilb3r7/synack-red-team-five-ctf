from pwn import remote
from hashlib import md5
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# our md5 colliders https://stackoverflow.com/questions/1756004/can-two-different-strings-generate-the-same-md5-hash-code
msg1 = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2'
msg2 = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2'

# order of the curve used for signing
n  = 115792089210356248762697446949407573529996955224135760342422259061068512044369

io = remote('178.128.162.158',31681)

ct = bytes.fromhex(io.recvline().strip().decode().split(': ')[1])
iv = bytes.fromhex(io.recvline().strip().decode().split(': ')[1])

# 'Enter your message in hex: '
io.recv()

io.sendline(msg1.encode())
m1 =  io.recvline().strip().decode().split(': ')[1]
r1 = int(io.recvline().strip().decode().split(': ')[1], 16)
s1 = int(io.recvline().strip().decode().split(': ')[1], 16)

# 'Enter your message in hex: '
io.recv()

io.sendline(msg2.encode())
m2 =  io.recvline().strip().decode().split(': ')[1]
r2 = int(io.recvline().strip().decode().split(': ')[1], 16)
s2 = int(io.recvline().strip().decode().split(': ')[1], 16)

assert m1 == msg1
assert m2 == msg2
assert r1 == r2

# doesn't use a hash value as is typical, uses long instead
h1 = bytes_to_long(bytes.fromhex(msg1))
h2 = bytes_to_long(bytes.fromhex(msg2))

# private key
x = (h1*s2 - h2*s1) * pow( (r1*(s1-s2)), -1, n ) % n

#decryption
key = md5(long_to_bytes(x)).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct),16)

print(pt.decode())
# HTB{r3u53d_n0nc35?n4h-w3_g0t_d3t3rm1n15t1c-n0nc3s!}
