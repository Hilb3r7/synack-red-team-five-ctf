import base64
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes


def encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.encrypt(data)

def decrypt(ct:bytes , key:bytes) -> bytes:
    cipher = AES.new(key, mode=AES.MODE_ECB)
    return cipher.decrypt(ct)

def unpad(pt):
    length = pt[-1]
    return pt[:-length]

def decrypt_dual(ct, key1, key2):
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    pt1 = cipher.decrypt(ct)
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    pt2 = cipher.decrypt(pt1)
    return unpad(pt2)


# via source python2 h = random.getrandbits(BIT_SIZE) with 16 LSB then zerod out
h = 27534775351079738483622454743638381042593424795345717535038924797978770210816

encrypted_flag = 'AvWAVwZDNyLpR0mQmwRAlPA9vrAD0B0hWL1vYCSkZ8EsxmBvqzx0RbysfUf3EtqpvH9kYcE1LXNFQzr/nBXCQQ=='
encrypted_flag = base64.b64decode(encrypted_flag)

# ECB so we only need to care about a single block for the messages
packet6 = 'AgRpcoSqVlXyMTVbgHznOt1aMzr4YrgXKvWOXgSsHHkXwbWDKiAZBCExnkV0pG5XHuvHVbvgSMwljsoWguYD4hdknp5hpUw0/Lg+O0HZQ1pwfsBYVQZIPHcn374uNi3YCq1Z5YXbkC/W4a9YZ4Bv1qSREdCu0+ehm2RCf+X/s5B+OXI2B6QyGRMruHMzsBEytnFok7CQkD7ak5jFI3D9Sw=='
packet6 = base64.b64decode(packet6)[:32]

# guessing 52
pt = b'Report Day 52:\n    Mainframe: Se'


print("storing encyptions...")
encrypted_pts = {}
for i in range(2**16):
    key = long_to_bytes(h + i)
    ct = encrypt(pt, key)
    encrypted_pts[ct] = i

print("checking for matches...")
for i in range(2**16):
    key = long_to_bytes(h + i)
    ct = decrypt(packet6, key)
    if ct in encrypted_pts:
        print(f"Match found! key1= h+{encrypted_pts[ct]}, key2= h+{i}")
        print(decrypt_dual(encrypted_flag, long_to_bytes(h + encrypted_pts[ct]), long_to_bytes(h + i)))
        break
