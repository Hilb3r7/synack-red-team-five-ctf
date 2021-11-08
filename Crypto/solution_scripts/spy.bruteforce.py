import base64
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

def is_valid_pad(pt):
    length = pt[-1]
    padding = bytes([length]) * length
    return pt[-length:] == padding

def unpad(pt):
    length = pt[-1]
    return pt[:-length]

def decrypt(ct, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.decrypt(ct)

# via source python2 h = random.getrandbits(BIT_SIZE) with 16 LSB then zerod out
h = 27534775351079738483622454743638381042593424795345717535038924797978770210816
encrypted_flag = 'AvWAVwZDNyLpR0mQmwRAlPA9vrAD0B0hWL1vYCSkZ8EsxmBvqzx0RbysfUf3EtqpvH9kYcE1LXNFQzr/nBXCQQ=='
encrypted_flag_bytes = base64.b64decode(encrypted_flag)

i = 0
found = False
while not found:
    print(i)
    key2 = long_to_bytes(h + i)
    i += 1
    intermediate = decrypt(encrypted_flag_bytes, key2)
    for j in range(2**16):
        key1 = long_to_bytes(h + j)
        pt = decrypt(intermediate, key1)
        if pt[:4] == b'HTB{' and is_valid_pad(pt):
            print(f"flag: {unpad(pt).decode()}\nkey1 = h + {i}\nkey2 = h + {j}")
            found = True
            break
